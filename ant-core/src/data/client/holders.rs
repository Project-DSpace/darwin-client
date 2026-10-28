//! The nodes that served records read recently, so a read of a record again
//! asks the node that served it first, and looks the record up only if that
//! node can't serve it.
//!
//! A chunk read normally runs a lookup for the chunk's nearest nodes, however
//! recently the same chunk was read. Once the chunk cache has let a chunk go
//! (it holds a bounded number of bytes), reading it again costs a lookup.
//! This cache keeps only who served each record, a few hundred bytes an entry,
//! so a re-read goes straight to that node. Its entries are hints: a node that
//! no longer serves the record is forgotten, and the read falls back to the
//! ordinary lookup, which alone can establish that a record is absent.

use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::XorName;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard, PoisonError};
use web_time::{Duration, Instant};

/// How many records' holders are kept: as many as the chunk cache's chunks.
const HOLDER_CACHE_CAPACITY: usize = 1024;

/// How long a holder is kept after it served a record: as long as the
/// browser keeps a peer it contacted among the peers a lookup starts from.
pub(crate) const HOLDER_TTL: Duration = Duration::from_secs(15 * 60);

/// A node that served a record, and when.
struct Holder {
    peer: PeerId,
    addrs: Vec<MultiAddr>,
    served_at: Instant,
}

/// The nodes that served records read recently, by record address.
pub(crate) struct HolderCache {
    inner: Mutex<LruCache<XorName, Holder>>,
    ttl: Duration,
}

impl HolderCache {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN),
            )),
            ttl,
        }
    }

    fn holders(&self) -> MutexGuard<'_, LruCache<XorName, Holder>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The node that served `address` within the last [`HOLDER_TTL`], with
    /// the addresses it was reached at.
    pub(crate) fn get(&self, address: &XorName) -> Option<(PeerId, Vec<MultiAddr>)> {
        let mut holders = self.holders();
        let fresh = holders
            .get(address)
            .map(|holder| holder.served_at.elapsed() < self.ttl)?;
        if !fresh {
            holders.pop(address);
            return None;
        }
        holders
            .get(address)
            .map(|holder| (holder.peer, holder.addrs.clone()))
    }

    /// `peer`, reached at `addrs`, served `address` just now.
    pub(crate) fn note(&self, address: XorName, peer: PeerId, addrs: Vec<MultiAddr>) {
        self.holders().put(
            address,
            Holder {
                peer,
                addrs,
                served_at: Instant::now(),
            },
        );
    }

    /// The node last noted for `address` didn't serve it when asked again.
    pub(crate) fn forget(&self, address: &XorName) {
        self.holders().pop(address);
    }
}

impl Default for HolderCache {
    fn default() -> Self {
        Self::new(HOLDER_CACHE_CAPACITY, HOLDER_TTL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    #[test]
    fn a_holder_is_kept_until_it_expires_or_is_forgotten() {
        let holders = HolderCache::default();
        assert!(holders.get(&[1; 32]).is_none());
        holders.note([1; 32], peer(7), Vec::new());
        assert_eq!(holders.get(&[1; 32]).map(|(p, _)| p), Some(peer(7)));
        // The latest holder replaces an earlier one.
        holders.note([1; 32], peer(8), Vec::new());
        assert_eq!(holders.get(&[1; 32]).map(|(p, _)| p), Some(peer(8)));
        holders.forget(&[1; 32]);
        assert!(holders.get(&[1; 32]).is_none());

        let expiring = HolderCache::new(8, Duration::ZERO);
        expiring.note([2; 32], peer(9), Vec::new());
        assert!(expiring.get(&[2; 32]).is_none());
    }

    #[test]
    fn holders_are_bounded_and_the_least_recently_used_goes() {
        let holders = HolderCache::new(2, HOLDER_TTL);
        holders.note([1; 32], peer(1), Vec::new());
        holders.note([2; 32], peer(2), Vec::new());
        let _ = holders.get(&[1; 32]);
        holders.note([3; 32], peer(3), Vec::new());
        assert!(holders.get(&[1; 32]).is_some());
        assert!(holders.get(&[2; 32]).is_none());
        assert!(holders.get(&[3; 32]).is_some());
    }

    #[test]
    fn a_holder_is_kept_for_fifteen_minutes_and_as_many_as_the_chunk_cache() {
        assert_eq!(HOLDER_TTL, Duration::from_secs(15 * 60));
        assert_eq!(HOLDER_CACHE_CAPACITY, 1024);
    }
}
