//! The listings producer's store: one LMDB environment that each part of
//! the producer keeps its state in, in named databases of its own.
//!
//! [`Producer`](super::listings_serve::Producer) keeps here everything that
//! must outlast a restart:
//!
//! - chain facts and envelopes, read once and kept
//!   ([`ListingChain::with_store`](super::listings::ListingChain::with_store)),
//!   in databases named [`FACTS`]`…`;
//! - the census of nodes ([`Census`](super::listings_census::Census)), named
//!   [`CENSUS`]`…`;
//! - each node's mirror, and what was decided from them
//!   ([`Producer`](super::listings_serve::Producer)), named [`SERVE`]`…`;
//! - the published index and its feed
//!   ([`Publisher`](super::listings_publish::Publisher)), named
//!   [`PUBLISH`]`…`.
//!
//! Each part creates the databases it needs with [`ListingsStore::database`],
//! which refuses a name without one of those prefixes, and reads and writes
//! them in transactions of [`ListingsStore::env`]. Read transactions are not
//! tied to a thread (heed's `WithoutTls`), so a task may open one on any
//! worker thread; none should be held across an `.await`.
//!
//! The environment's files (`data.mdb`, `lock.mdb`) are in the store's
//! directory, beside [`LOCK_FILE`], which one process holds locked while the
//! store is open: a second producer pointed at the same directory is refused
//! rather than writing over the first one's state.
//!
//! The map is sized when the store opens, as darwin-node sizes its listing
//! store's: what the store holds, plus the free space on its disk (on Windows
//! at most [`WINDOWS_MAP_HEADROOM`] of it, whose cost in committed memory
//! grows with the map), and at least [`MIN_MAP_SIZE`]. The store fills only
//! when its disk does; opened again once space is freed, it has room again.
//! Unlike a node's store, it keeps no reserve: the producer's disk is watched
//! from its `status.json` (`resources.disk_free_bytes`).

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs2::FileExt;
use heed::{Database, Env, EnvOpenOptions, WithoutTls};

use crate::data::error::{Error, Result};

/// The prefix of the databases holding chain facts and envelopes.
pub const FACTS: &str = "facts_";

/// The prefix of the census's databases.
pub const CENSUS: &str = "census_";

/// The prefix of the databases holding node mirrors and decisions.
pub const SERVE: &str = "serve_";

/// The prefix of the published index's databases.
pub const PUBLISH: &str = "publish_";

/// Every prefix a database's name may start with: one per part of the
/// producer.
pub const PREFIXES: [&str; 4] = [FACTS, CENSUS, SERVE, PUBLISH];

/// The file in the store's directory that the process using the store holds
/// locked.
pub const LOCK_FILE: &str = "store.lock";

/// How many named databases the environment can hold, across every part.
const MAX_DBS: u32 = 32;

/// The smallest map, whatever the disk: darwin-node's `MIN_MAP_SIZE` for its
/// listing store.
pub const MIN_MAP_SIZE: usize = 256 * 1024 * 1024;

/// The most free disk space the map takes in on Windows, where committed
/// memory grows with the mapped size (about 0.2% of it): darwin-node's
/// `WINDOWS_MAP_HEADROOM` for its listing store.
pub const WINDOWS_MAP_HEADROOM: u64 = 32 * 1024 * 1024 * 1024;

/// The map's size is rounded up to a multiple of this: a multiple of every
/// page size LMDB runs with (4, 16 or 64 KiB).
const MAP_ALIGN: u64 = 64 * 1024;

/// The producer's store. Cloning it is cheap; every clone uses the same
/// environment, and the lock is held until the last one is dropped.
#[derive(Clone)]
pub struct ListingsStore {
    env: Env<WithoutTls>,
    dir: PathBuf,
    /// Locked while the store is open (see [`LOCK_FILE`]).
    _lock: Arc<File>,
}

impl std::fmt::Debug for ListingsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListingsStore")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl ListingsStore {
    /// Open the store in `dir`, creating the directory and the environment
    /// if they don't exist.
    ///
    /// # Errors
    ///
    /// If the directory can't be created, another process has the store
    /// open, the disk can't be measured, or LMDB can't open the environment.
    pub fn open(dir: &Path) -> Result<Self> {
        Self::open_sized(dir, None)
    }

    /// [`Self::open`], with a map of `map_size` bytes instead of one sized
    /// from the disk: for tests, which open many small stores.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    #[cfg(test)]
    pub(crate) fn open_with_map_size(dir: &Path, map_size: usize) -> Result<Self> {
        Self::open_sized(dir, Some(map_size))
    }

    #[allow(unsafe_code)]
    fn open_sized(dir: &Path, map_size: Option<usize>) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| {
            Error::Storage(format!(
                "could not create the listings store's directory {}: {e}",
                dir.display()
            ))
        })?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(LOCK_FILE))
            .map_err(|e| {
                Error::Storage(format!(
                    "could not open the listings store's lock file in {}: {e}",
                    dir.display()
                ))
            })?;
        lock.try_lock_exclusive().map_err(|e| {
            Error::Storage(format!(
                "the listings store in {} is open in another process: {e}",
                dir.display()
            ))
        })?;
        let map_size = match map_size {
            Some(size) => size,
            None => disk_map_size(dir)?,
        };
        let mut options = EnvOpenOptions::new().read_txn_without_tls();
        options.map_size(map_size).max_dbs(MAX_DBS);
        // SAFETY: `open` is unsafe because LMDB maps the environment's file
        // into memory, and another process writing to it, or this process
        // opening it twice, could change that memory under the references
        // heed hands out. The lock taken above keeps every other process
        // that opens the store through this type out until this one ends,
        // and heed refuses to open one environment twice in a process.
        let env = unsafe { options.open(dir) }.map_err(|e| {
            Error::Storage(format!(
                "could not open the listings store in {}: {e}",
                dir.display()
            ))
        })?;
        Ok(Self {
            env,
            dir: dir.to_path_buf(),
            _lock: Arc::new(lock),
        })
    }

    /// The LMDB environment, for transactions on the databases a part
    /// created with [`Self::database`].
    #[must_use]
    pub fn env(&self) -> &Env<WithoutTls> {
        &self.env
    }

    /// The store's directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The database `name`, created if it doesn't exist, with the key and
    /// value codecs `KC` and `DC`. The name must start with one of
    /// [`PREFIXES`] and go on after it: the part of the producer it belongs
    /// to. Open each database once, and keep the handle.
    ///
    /// # Errors
    ///
    /// If the name has no part's prefix, or LMDB can't create it (such as
    /// when the environment already holds as many databases as it can).
    pub fn database<KC: 'static, DC: 'static>(&self, name: &str) -> Result<Database<KC, DC>> {
        if !PREFIXES
            .iter()
            .any(|prefix| name.len() > prefix.len() && name.starts_with(prefix))
        {
            return Err(Error::Storage(format!(
                "listings store: the database name {name:?} doesn't start with a part's \
                 prefix ({})",
                PREFIXES.join(", ")
            )));
        }
        let mut txn = self.env.write_txn().map_err(store_error)?;
        let database = self
            .env
            .create_database(&mut txn, Some(name))
            .map_err(store_error)?;
        txn.commit().map_err(store_error)?;
        Ok(database)
    }

    /// The size of the store's data file, in bytes: `status.json`'s
    /// `resources.store_bytes`.
    ///
    /// # Errors
    ///
    /// If the file can't be measured.
    pub fn size_bytes(&self) -> Result<u64> {
        self.env.real_disk_size().map_err(store_error)
    }
}

/// An LMDB error, as the store reports it.
pub fn store_error(error: heed::Error) -> Error {
    Error::Storage(format!("listings store: {error}"))
}

/// The map's size for a store in `dir`: darwin-node's rule for its listing
/// store, with no reserve. What the store's data file holds, plus the free
/// space on the disk (on Windows, at most [`WINDOWS_MAP_HEADROOM`]), rounded
/// up to [`MAP_ALIGN`], and at least [`MIN_MAP_SIZE`].
fn disk_map_size(dir: &Path) -> Result<usize> {
    let available = fs2::available_space(dir).map_err(|e| {
        Error::Storage(format!(
            "could not measure the free space for the listings store in {}: {e}",
            dir.display()
        ))
    })?;
    #[cfg(windows)]
    let available = available.min(WINDOWS_MAP_HEADROOM);
    // The data file is missing only before the store's first open. Any other
    // failure to measure it is no reason to size the map as though the store
    // were empty, which would make it too small to open.
    let data = dir.join("data.mdb");
    let held = match std::fs::metadata(&data) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            return Err(Error::Storage(format!(
                "could not measure {}: {e}",
                data.display()
            )))
        }
    };
    Ok(map_size_for(held, available))
}

/// [`disk_map_size`]'s arithmetic: `held` bytes in the store and `available`
/// free.
fn map_size_for(held: u64, available: u64) -> usize {
    let target = held.saturating_add(available);
    let aligned = target.div_ceil(MAP_ALIGN).saturating_mul(MAP_ALIGN);
    usize::try_from(aligned)
        .unwrap_or(usize::MAX)
        .max(MIN_MAP_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use heed::types::{Bytes, Str};

    /// A small map: tests open many stores.
    const TEST_MAP: usize = 16 * 1024 * 1024;

    #[test]
    fn a_part_keeps_its_databases_across_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store");
        {
            let store = ListingsStore::open_with_map_size(&path, TEST_MAP).unwrap();
            let database: Database<Str, Bytes> = store.database("census_nodes").unwrap();
            let mut txn = store.env().write_txn().unwrap();
            database.put(&mut txn, "a", b"one").unwrap();
            txn.commit().unwrap();
            assert!(store.size_bytes().unwrap() > 0);
        }
        let store = ListingsStore::open_with_map_size(&path, TEST_MAP).unwrap();
        let database: Database<Str, Bytes> = store.database("census_nodes").unwrap();
        let txn = store.env().read_txn().unwrap();
        assert_eq!(database.get(&txn, "a").unwrap(), Some(&b"one"[..]));
        assert_eq!(store.dir(), path);
    }

    #[test]
    fn a_name_without_a_parts_prefix_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = ListingsStore::open_with_map_size(dir.path(), TEST_MAP).unwrap();
        for name in ["nodes", "facts_", "census", "publishing", "Serve_mirrors"] {
            assert!(
                store.database::<Str, Bytes>(name).is_err(),
                "{name} was taken"
            );
        }
        for prefix in PREFIXES {
            store.database::<Str, Bytes>(&format!("{prefix}x")).unwrap();
        }
    }

    #[test]
    fn a_store_open_elsewhere_is_refused_until_it_closes() {
        let dir = tempfile::tempdir().unwrap();
        let store = ListingsStore::open_with_map_size(dir.path(), TEST_MAP).unwrap();
        let clone = store.clone();
        drop(store);
        // A clone keeps it open.
        assert!(ListingsStore::open_with_map_size(dir.path(), TEST_MAP).is_err());
        drop(clone);
        ListingsStore::open_with_map_size(dir.path(), TEST_MAP).unwrap();
    }

    #[test]
    fn the_map_covers_what_the_store_holds_and_the_free_disk() {
        const GIB: u64 = 1024 * 1024 * 1024;
        // Never below the minimum.
        assert_eq!(map_size_for(0, 0), MIN_MAP_SIZE);
        // What is held is always covered, however little is free.
        assert_eq!(map_size_for(3 * GIB, 0) as u64, 3 * GIB);
        // Rounded up.
        assert_eq!(map_size_for(GIB, 1) as u64, GIB + MAP_ALIGN);
        assert_eq!(map_size_for(GIB, 100 * GIB) as u64, 101 * GIB);
        // No overflow.
        assert_eq!(map_size_for(u64::MAX, u64::MAX), usize::MAX);
    }

    #[test]
    fn a_store_sized_from_the_disk_opens() {
        let dir = tempfile::tempdir().unwrap();
        let store = ListingsStore::open(dir.path()).unwrap();
        let size = store.env().info().map_size;
        assert!(size >= MIN_MAP_SIZE);
        #[cfg(windows)]
        assert!(size as u64 <= WINDOWS_MAP_HEADROOM + MAP_ALIGN);
        // The data file holds what is stored, not the whole map.
        let file = std::fs::metadata(dir.path().join("data.mdb"))
            .unwrap()
            .len();
        assert!(file < MIN_MAP_SIZE as u64, "data.mdb is {file} bytes");
    }
}
