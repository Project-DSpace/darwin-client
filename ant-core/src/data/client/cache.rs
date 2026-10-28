//! LRU chunk cache for reducing redundant network requests.
//!
//! Caches recently fetched chunks in memory to avoid re-fetching
//! the same content-addressed data from the network.

use ant_protocol::XorName;
use bytes::Bytes;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Mutex, PoisonError};

/// Default cache capacity (number of chunks).
const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// One mebibyte, in bytes.
const MIB: usize = 1024 * 1024;

/// The most bytes the default cache holds, whatever the memory: 256 MiB.
pub const DEFAULT_CACHE_MAX_BYTES: usize = 256 * MIB;

/// The least bytes the default cache holds: one full chunk, 4 MiB.
const DEFAULT_CACHE_MIN_BYTES: usize = 4 * MIB;

/// The share of the memory free for use when a client is built that its
/// default cache may hold: an eighth, beside the quarter a streamed
/// download's decrypt batches may take.
const DEFAULT_CACHE_MEMORY_DIVISOR: u64 = 8;

/// The default cache's byte budget for `usable` bytes of memory free for use:
/// an eighth of it, at least one full chunk and at most
/// [`DEFAULT_CACHE_MAX_BYTES`]. Unknown memory gets the most.
#[must_use]
pub fn default_cache_bytes(usable: Option<u64>) -> usize {
    match usable {
        None => DEFAULT_CACHE_MAX_BYTES,
        Some(usable) => usize::try_from(usable / DEFAULT_CACHE_MEMORY_DIVISOR)
            .unwrap_or(usize::MAX)
            .clamp(DEFAULT_CACHE_MIN_BYTES, DEFAULT_CACHE_MAX_BYTES),
    }
}

/// The chunks cached, and the bytes they hold.
struct Cached {
    entries: LruCache<XorName, Bytes>,
    bytes: usize,
}

/// An LRU cache for content-addressed chunks, bounded by a number of chunks
/// and, for the default cache, by the bytes they hold.
pub struct ChunkCache {
    inner: Mutex<Cached>,
    /// The most bytes the cached chunks may hold, if bounded.
    max_bytes: Option<usize>,
}

impl ChunkCache {
    /// Create a new chunk cache with the given capacity, in chunks, and no
    /// bound on the bytes they hold.
    ///
    /// Falls back to the default capacity (1024) if zero is provided.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::bounded(capacity, None)
    }

    /// Create a chunk cache of at most `capacity` chunks holding at most
    /// `max_bytes` bytes. A chunk larger than `max_bytes` is not cached.
    #[must_use]
    pub fn with_byte_budget(capacity: usize, max_bytes: usize) -> Self {
        Self::bounded(capacity, Some(max_bytes))
    }

    fn bounded(capacity: usize, max_bytes: Option<usize>) -> Self {
        // Use provided capacity, falling back to default if zero
        let effective = if capacity == 0 {
            DEFAULT_CACHE_CAPACITY
        } else {
            capacity
        };
        // SAFETY: effective is guaranteed non-zero by the check above
        let cap = NonZeroUsize::new(effective).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Mutex::new(Cached {
                entries: LruCache::new(cap),
                bytes: 0,
            }),
            max_bytes,
        }
    }

    /// Create the default cache: 1,024 chunks at most, holding at most an
    /// eighth of the memory free for use when it is built, between one full
    /// chunk and [`DEFAULT_CACHE_MAX_BYTES`] ([`default_cache_bytes`]). A
    /// caller that wants a larger cache gives the client one
    /// (`Client::with_chunk_cache`).
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::with_byte_budget(DEFAULT_CACHE_CAPACITY, default_cache_bytes(usable_memory()))
    }

    /// The most bytes the cached chunks may hold, if bounded.
    #[must_use]
    pub fn max_bytes(&self) -> Option<usize> {
        self.max_bytes
    }

    fn cached(&self) -> std::sync::MutexGuard<'_, Cached> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Get a chunk from the cache.
    #[must_use]
    pub fn get(&self, address: &XorName) -> Option<Bytes> {
        self.cached().entries.get(address).cloned()
    }

    /// Insert a chunk into the cache, evicting the least recently used
    /// chunks until the cache is within its bounds again. A chunk larger than
    /// the byte bound is not cached.
    pub fn put(&self, address: XorName, content: Bytes) {
        if self.max_bytes.is_some_and(|max| content.len() > max) {
            self.remove(&address);
            return;
        }
        let mut cached = self.cached();
        let added = content.len();
        if let Some((_, evicted)) = cached.entries.push(address, content) {
            cached.bytes = cached.bytes.saturating_sub(evicted.len());
        }
        cached.bytes = cached.bytes.saturating_add(added);
        if let Some(max) = self.max_bytes {
            while cached.bytes > max {
                let Some((_, evicted)) = cached.entries.pop_lru() else {
                    break;
                };
                cached.bytes = cached.bytes.saturating_sub(evicted.len());
            }
        }
    }

    /// Check if a chunk is in the cache.
    #[must_use]
    pub fn contains(&self, address: &XorName) -> bool {
        self.cached().entries.contains(address)
    }

    /// Get the number of cached chunks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cached().entries.len()
    }

    /// The bytes the cached chunks hold.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.cached().bytes
    }

    /// Check if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove a specific entry from the cache.
    pub fn remove(&self, address: &XorName) {
        let mut cached = self.cached();
        if let Some(removed) = cached.entries.pop(address) {
            cached.bytes = cached.bytes.saturating_sub(removed.len());
        }
    }

    /// Clear all cached chunks.
    pub fn clear(&self) {
        let mut cached = self.cached();
        cached.entries.clear();
        cached.bytes = 0;
    }
}

impl Default for ChunkCache {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

/// The memory free for use now, where it can be read.
#[cfg(feature = "native")]
fn usable_memory() -> Option<u64> {
    crate::data::client::file::usable_memory_bytes()
}

/// A browser can't read the memory free, so its default cache may hold the
/// most. The browser core gives its own clients smaller caches.
#[cfg(not(feature = "native"))]
fn usable_memory() -> Option<u64> {
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_address(byte: u8) -> XorName {
        let mut addr = [0u8; 32];
        addr[0] = byte;
        addr
    }

    #[test]
    fn test_new_cache_default_capacity() {
        let cache = ChunkCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_zero_capacity_falls_back_to_default() {
        let cache = ChunkCache::new(0);
        let addr = make_address(1);
        cache.put(addr, Bytes::from_static(b"hello"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_put_and_get() {
        let cache = ChunkCache::new(10);
        let addr = make_address(1);
        let data = Bytes::from_static(b"hello world");

        cache.put(addr, data.clone());
        let got = cache.get(&addr);
        assert_eq!(got, Some(data));
    }

    #[test]
    fn test_get_miss() {
        let cache = ChunkCache::new(10);
        let addr = make_address(1);
        assert_eq!(cache.get(&addr), None);
    }

    #[test]
    fn test_contains() {
        let cache = ChunkCache::new(10);
        let addr = make_address(1);
        assert!(!cache.contains(&addr));

        cache.put(addr, Bytes::from_static(b"data"));
        assert!(cache.contains(&addr));
    }

    #[test]
    fn test_lru_eviction() {
        let cache = ChunkCache::new(2);

        let addr1 = make_address(1);
        let addr2 = make_address(2);
        let addr3 = make_address(3);

        cache.put(addr1, Bytes::from_static(b"one"));
        cache.put(addr2, Bytes::from_static(b"two"));
        assert_eq!(cache.len(), 2);

        // Inserting a third should evict addr1 (least recently used)
        cache.put(addr3, Bytes::from_static(b"three"));
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&addr1));
        assert!(cache.contains(&addr2));
        assert!(cache.contains(&addr3));
    }

    #[test]
    fn test_lru_access_refreshes() {
        let cache = ChunkCache::new(2);

        let addr1 = make_address(1);
        let addr2 = make_address(2);
        let addr3 = make_address(3);

        cache.put(addr1, Bytes::from_static(b"one"));
        cache.put(addr2, Bytes::from_static(b"two"));

        // Access addr1 to refresh it
        let _ = cache.get(&addr1);

        // Now inserting addr3 should evict addr2 (least recently used)
        cache.put(addr3, Bytes::from_static(b"three"));
        assert!(cache.contains(&addr1));
        assert!(!cache.contains(&addr2));
        assert!(cache.contains(&addr3));
    }

    #[test]
    fn test_clear() {
        let cache = ChunkCache::new(10);
        cache.put(make_address(1), Bytes::from_static(b"one"));
        cache.put(make_address(2), Bytes::from_static(b"two"));
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn test_overwrite_same_key() {
        let cache = ChunkCache::new(10);
        let addr = make_address(1);

        cache.put(addr, Bytes::from_static(b"first"));
        cache.put(addr, Bytes::from_static(b"second"));

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&addr), Some(Bytes::from_static(b"second")));
        assert_eq!(cache.bytes(), b"second".len());
    }

    #[test]
    fn the_default_budget_is_an_eighth_of_free_memory_within_bounds() {
        const GIB: u64 = 1024 * 1024 * 1024;
        // A 2 GB host with about 1.5 GiB free: about 192 MiB.
        assert_eq!(default_cache_bytes(Some(3 * GIB / 2)), 192 * MIB);
        // Plenty of memory: at most 256 MiB, not the 4 GiB of 1,024 full chunks.
        assert_eq!(default_cache_bytes(Some(64 * GIB)), DEFAULT_CACHE_MAX_BYTES);
        assert_eq!(DEFAULT_CACHE_MAX_BYTES, 256 * MIB);
        // Very little: still one full chunk.
        assert_eq!(default_cache_bytes(Some(8 * 1024 * 1024)), 4 * MIB);
        assert_eq!(default_cache_bytes(Some(0)), 4 * MIB);
        // Unknown: the most.
        assert_eq!(default_cache_bytes(None), DEFAULT_CACHE_MAX_BYTES);
    }

    #[test]
    fn the_default_cache_is_bounded_by_bytes() {
        let cache = ChunkCache::default();
        let max = cache
            .max_bytes()
            .expect("the default cache has a byte bound");
        assert!((4 * MIB..=DEFAULT_CACHE_MAX_BYTES).contains(&max), "{max}");
        // Full chunks past the bound evict the oldest: the cache never holds
        // more than its bound, however many are read.
        let chunk = Bytes::from(vec![7u8; 4 * MIB]);
        for byte in 0..=u8::try_from(max / (4 * MIB) + 2).unwrap() {
            cache.put(make_address(byte), chunk.clone());
            assert!(cache.bytes() <= max, "{} > {max}", cache.bytes());
        }
        assert_eq!(cache.len(), max / (4 * MIB));
        assert!(cache.contains(&make_address(u8::try_from(max / (4 * MIB) + 2).unwrap())));
        assert!(!cache.contains(&make_address(0)));
    }

    #[test]
    fn a_byte_budget_evicts_least_recently_used_chunks_first() {
        let cache = ChunkCache::with_byte_budget(10, 10);
        cache.put(make_address(1), Bytes::from_static(b"aaaa"));
        cache.put(make_address(2), Bytes::from_static(b"bbbb"));
        let _ = cache.get(&make_address(1));
        cache.put(make_address(3), Bytes::from_static(b"cccc"));
        // 12 bytes over 10: the least recently used, 2, goes.
        assert!(cache.contains(&make_address(1)));
        assert!(!cache.contains(&make_address(2)));
        assert!(cache.contains(&make_address(3)));
        assert_eq!(cache.bytes(), 8);
        // A chunk larger than the whole budget isn't cached, and leaves the
        // rest in place.
        cache.put(make_address(4), Bytes::from(vec![0u8; 11]));
        assert!(!cache.contains(&make_address(4)));
        assert_eq!(cache.len(), 2);
        cache.remove(&make_address(1));
        assert_eq!(cache.bytes(), 4);
    }

    #[test]
    fn a_count_only_cache_keeps_its_count_bound() {
        let cache = ChunkCache::new(8);
        assert_eq!(cache.max_bytes(), None);
        for byte in 0..10 {
            cache.put(make_address(byte), Bytes::from(vec![0u8; 1024]));
        }
        assert_eq!(cache.len(), 8);
        assert_eq!(cache.bytes(), 8 * 1024);
    }
}
