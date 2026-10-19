//! What a node's change feed carries, and the address ranges readers ask
//! about.
//!
//! Besides its index, a node keeps a change feed of the listings it serves in
//! the index: one record per address, numbered in the order the changes were
//! made ([`FeedChange`]). A record is the listing's [`DigestEntry`], about 80
//! bytes where the listing can take several kilobytes, or the address's
//! removal. When an address changes again its record is numbered again, so
//! the feed holds the latest change to each address, and a removal needs no
//! expiry. Records are numbered from 1 within an epoch: a random number,
//! never 0, that a node chooses when it first numbers its listings, and
//! again whenever it has to number them afresh.
//!
//! A reader asks a node for the changes in an [`AddressRange`] after the last
//! record it has seen ([`ChangesRequest`](crate::ChangesRequest)), and keeps
//! a mirror of what the node serves there
//! ([`FeedSync`](crate::FeedSync)). With each answer the node gives the
//! number of entries it serves in the range and their [`SetHash`], so the
//! reader can tell whether its mirror is exact. A set hash is updated as
//! entries come and go, in any order, and adds up over ranges, so a node can
//! keep one for each address prefix and add up those a range covers.
//!
//! [`leaves`] splits the address space into the ranges a reader asks each
//! node about, so that the nodes nearest any address are all asked about it.
//!
//! Nothing here does I/O.

use crate::listing::{Listing, ListingKey};
use crate::walk::NEAREST_NODES;
use crate::wire::{put_option_varint, put_varint};
use ant_protocol::{compute_address, XorName};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Sub, SubAssign};

/// A listing copy as a node's change feed carries it: where it sits in the
/// index, the `first_seen` the node recorded, and a
/// [digest](Listing::digest) of the rest.
///
/// Copies with the same digest are one listing, as
/// [`merge_copies`](crate::merge_copies) merges them; each keeps its own
/// `first_seen` for dating it. Only listings in the index have entries: those
/// a [`ListRequest`](crate::ListingsBody::ListRequest) returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DigestEntry {
    /// The file's address.
    pub address: XorName,
    /// The listing's time in the index: its key's (see [`Listing::key`]).
    pub time: u64,
    /// Its key's block number.
    pub block_number: u64,
    /// Its key's log index.
    pub log_index: u64,
    /// The `first_seen` the node recorded, if the listing has one.
    pub first_seen: Option<u64>,
    /// The listing's [digest](Listing::digest).
    pub digest: [u8; 32],
}

impl DigestEntry {
    /// The entry for `listing`.
    #[must_use]
    pub fn new(listing: &Listing) -> Self {
        let key = listing.key();
        Self {
            address: listing.address,
            time: key.time,
            block_number: key.block_number,
            log_index: key.log_index,
            first_seen: listing.first_seen,
            digest: listing.digest(),
        }
    }

    /// The listing's key.
    #[must_use]
    pub fn key(&self) -> ListingKey {
        ListingKey {
            time: self.time,
            block_number: self.block_number,
            log_index: self.log_index,
            address: self.address,
        }
    }

    /// Whether this is the entry for `listing`, as [`new`](Self::new) makes
    /// it: the same address, key, `first_seen` and digest. Check a listing
    /// fetched for an entry ([`GetRequest`](crate::ListingsBody::GetRequest))
    /// with this before taking it as the copy the entry stands for.
    #[must_use]
    pub fn describes(&self, listing: &Listing) -> bool {
        *self == Self::new(listing)
    }

    /// The entry's postcard encoding, written out so that it can't fail.
    fn wire_bytes(&self) -> Vec<u8> {
        let Self {
            address,
            time,
            block_number,
            log_index,
            first_seen,
            digest,
        } = self;
        let mut out = Vec::with_capacity(32 + 4 * 10 + 1 + 32);
        out.extend_from_slice(address);
        put_varint(&mut out, *time);
        put_varint(&mut out, *block_number);
        put_varint(&mut out, *log_index);
        put_option_varint(&mut out, *first_seen);
        out.extend_from_slice(digest);
        out
    }
}

/// One record of a node's change feed: the latest change to what the node
/// serves in the index at one address, numbered `seq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedChange {
    /// The node serves the listing this entry describes.
    Entry {
        /// The record's number in the feed.
        seq: u64,
        /// The listing's entry.
        entry: DigestEntry,
    },
    /// The node serves no listing at this address any more.
    Removed {
        /// The record's number in the feed.
        seq: u64,
        /// The address.
        address: XorName,
    },
}

impl FeedChange {
    /// The record's number in the feed.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        match self {
            Self::Entry { seq, .. } | Self::Removed { seq, .. } => *seq,
        }
    }

    /// The address that changed.
    #[must_use]
    pub const fn address(&self) -> XorName {
        match self {
            Self::Entry { entry, .. } => entry.address,
            Self::Removed { address, .. } => *address,
        }
    }

    /// The entry the node serves at the address now, if any.
    #[must_use]
    pub const fn entry(&self) -> Option<&DigestEntry> {
        match self {
            Self::Entry { entry, .. } => Some(entry),
            Self::Removed { .. } => None,
        }
    }
}

/// The set hash of digest entries: the sum, modulo 2^256, of each entry's
/// BLAKE3 hash ([`SetHash::of_entry`]), each read as a little-endian number.
/// The sum doesn't depend on the order the entries came in, is updated by
/// adding and subtracting as entries come and go, and adds up over sets with
/// no entry in common, so a node can keep one for each address prefix and
/// add up those a range covers. Unlike an XOR of the hashes, it doesn't
/// cancel an entry counted twice.
///
/// With the count of entries, it tells a reader whether its mirror holds the
/// entries a node reports serving. It doesn't tell whether the node reports
/// what it serves: a node can say anything, however its hash is made.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SetHash([u8; 32]);

impl SetHash {
    /// The set hash of no entries: zero.
    pub const EMPTY: Self = Self([0; 32]);

    /// The set hash of `entries`. An entry given twice counts twice.
    pub fn of<'a>(entries: impl IntoIterator<Item = &'a DigestEntry>) -> Self {
        entries.into_iter().map(Self::of_entry).sum()
    }

    /// One entry's part of a set hash: BLAKE3 of its wire bytes, as a
    /// [`RangeListResponse`](crate::RangeListResponse) carries it.
    #[must_use]
    pub fn of_entry(entry: &DigestEntry) -> Self {
        Self(compute_address(&entry.wire_bytes()))
    }

    /// Add `entry` to the set.
    pub fn insert(&mut self, entry: &DigestEntry) {
        *self += Self::of_entry(entry);
    }

    /// Take `entry` out of the set.
    pub fn remove(&mut self, entry: &DigestEntry) {
        *self -= Self::of_entry(entry);
    }

    /// The sum as 32 bytes, little-endian, as it travels.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Read [`to_bytes`](Self::to_bytes) back.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AddAssign for SetHash {
    /// The set hash of the union of two sets with no entry in common.
    fn add_assign(&mut self, other: Self) {
        let mut carry = 0u16;
        for (byte, other) in self.0.iter_mut().zip(other.0) {
            let sum = u16::from(*byte) + u16::from(other) + carry;
            *byte = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
    }
}

impl SubAssign for SetHash {
    /// The set hash of a set without a subset of it.
    fn sub_assign(&mut self, other: Self) {
        let mut borrow = 0u16;
        for (byte, other) in self.0.iter_mut().zip(other.0) {
            let difference = 0x100 + u16::from(*byte) - u16::from(other) - borrow;
            *byte = difference.to_le_bytes()[0];
            borrow = u16::from(difference < 0x100);
        }
    }
}

impl Add for SetHash {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl Sub for SetHash {
    type Output = Self;

    fn sub(mut self, other: Self) -> Self {
        self -= other;
        self
    }
}

impl Sum for SetHash {
    fn sum<I: Iterator<Item = Self>>(hashes: I) -> Self {
        hashes.fold(Self::EMPTY, Add::add)
    }
}

impl fmt::Debug for SetHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SetHash(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// The hash a node gives as its `view` in a
/// [`ChangesResponse`](crate::ChangesResponse): BLAKE3 of its nearest peers'
/// ids in increasing order, without repeats, one after another. A reader
/// that sees it change asks for the list
/// ([`ChangesRequest::want_peers`](crate::ChangesRequest::want_peers)) and
/// checks it against the hash.
#[must_use]
pub fn view_hash(peers: &[[u8; 32]]) -> [u8; 32] {
    let mut ids = peers.to_vec();
    ids.sort_unstable();
    ids.dedup();
    compute_address(&ids.concat())
}

/// The addresses whose first `bits` bits are those of a prefix: a part of the
/// address space a reader asks a node about. [`AddressRange::ALL`], of no
/// bits, is the whole space; a range has at most 255.
///
/// Ranges order by their first address, then by size, largest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddressRange {
    prefix: XorName,
    bits: u8,
}

impl AddressRange {
    /// The whole address space.
    pub const ALL: Self = Self {
        prefix: [0; 32],
        bits: 0,
    };

    /// The addresses whose first `bits` bits are those of `prefix`. The rest
    /// of `prefix` doesn't matter, and is cleared.
    #[must_use]
    pub fn new(mut prefix: XorName, bits: u8) -> Self {
        for (index, byte) in prefix.iter_mut().enumerate() {
            *byte &= fixed_bits(bits, index);
        }
        Self { prefix, bits }
    }

    /// The prefix, with the bits after the first [`bits`](Self::bits) clear.
    #[must_use]
    pub const fn prefix(&self) -> XorName {
        self.prefix
    }

    /// How many leading bits the range fixes.
    #[must_use]
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// Whether `address` is in the range.
    #[must_use]
    pub fn contains(&self, address: &XorName) -> bool {
        self.prefix
            .iter()
            .zip(address)
            .enumerate()
            .all(|(index, (prefix, byte))| byte & fixed_bits(self.bits, index) == *prefix)
    }

    /// Whether every address in `other` is in this range.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        other.bits >= self.bits && self.contains(&other.prefix)
    }

    /// The range's first address: the prefix.
    #[must_use]
    pub const fn first(&self) -> XorName {
        self.prefix
    }

    /// The range's last address: the prefix with every bit after the first
    /// [`bits`](Self::bits) set.
    #[must_use]
    pub fn last(&self) -> XorName {
        let mut last = self.prefix;
        for (index, byte) in last.iter_mut().enumerate() {
            *byte |= !fixed_bits(self.bits, index);
        }
        last
    }

    /// The range's two halves: the addresses whose next bit is 0, then those
    /// whose next bit is 1. `None` for a range of 255 bits.
    #[must_use]
    pub fn halves(&self) -> Option<(Self, Self)> {
        let bits = self.bits.checked_add(1)?;
        let mut upper = self.prefix;
        upper[usize::from(self.bits / 8)] |= 0x80 >> (self.bits % 8);
        Some((
            Self {
                prefix: self.prefix,
                bits,
            },
            Self {
                prefix: upper,
                bits,
            },
        ))
    }
}

/// The bits of byte `index` of an address that a range of `bits` bits fixes.
fn fixed_bits(bits: u8, index: usize) -> u8 {
    match usize::from(bits).saturating_sub(index * 8).min(8) {
        0 => 0,
        fixed => 0xff << (8 - fixed),
    }
}

/// A part of the address space and the nodes in it: one of the [`leaves`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    /// The part.
    pub range: AddressRange,
    /// The nodes whose ids are in it, as indexes into the ids given, in
    /// increasing order.
    pub nodes: Vec<usize>,
}

/// Split the address space into leaves for the nodes with these ids: from the
/// whole space down, a range is split into its halves only while both hold at
/// least [`NEAREST_NODES`] of the ids. So every leaf holds at least that many,
/// or all of them if there are fewer, and the [`NEAREST_NODES`] nodes nearest
/// any address by XOR distance are in its leaf: each node in the leaf shares
/// more leading bits with the address than any node outside it. A reader asks
/// each node about its own leaf.
///
/// The leaves come in address order and cover the space without
/// overlapping. An id given twice counts twice.
#[must_use]
pub fn leaves(ids: &[[u8; 32]]) -> Vec<Leaf> {
    let mut order: Vec<usize> = (0..ids.len()).collect();
    order.sort_unstable_by_key(|&index| (ids[index], index));
    let mut leaves = Vec::new();
    // Lower halves first, so the leaves come out in address order.
    let mut ranges = vec![(AddressRange::ALL, 0..order.len())];
    while let Some((range, span)) = ranges.pop() {
        let nodes = &order[span.clone()];
        let split = range.halves().and_then(|(lower, upper)| {
            // The ids in a range are sorted, so those in its lower half
            // come first.
            let cut = nodes.partition_point(|&index| lower.contains(&ids[index]));
            (cut >= NEAREST_NODES && nodes.len() - cut >= NEAREST_NODES)
                .then_some((lower, upper, cut))
        });
        match split {
            Some((lower, upper, cut)) => {
                ranges.push((upper, span.start + cut..span.end));
                ranges.push((lower, span.start..span.start + cut));
            }
            None => {
                let mut nodes = nodes.to_vec();
                nodes.sort_unstable();
                leaves.push(Leaf { range, nodes });
            }
        }
    }
    leaves
}

/// Which of `leaves`, as [`leaves`] gives them, holds `address`.
#[must_use]
pub fn leaf_index(leaves: &[Leaf], address: &XorName) -> Option<usize> {
    let after = leaves.partition_point(|leaf| leaf.range.first() <= *address);
    after
        .checked_sub(1)
        .filter(|&index| leaves[index].range.contains(address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Metadata;
    use crate::flags::{Flags, PaymentField};
    use crate::listing::ListingPayment;
    use crate::proof::decode_hex;
    use crate::walk::nearest_by_distance;
    use std::collections::{BTreeMap, HashSet};

    /// 32 bytes from `seed`, spread by splitmix64.
    fn id(seed: u64) -> [u8; 32] {
        let mut state = seed;
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
        }
        bytes
    }

    fn hex32(text: &str) -> [u8; 32] {
        decode_hex(text).unwrap().try_into().unwrap()
    }

    /// The listing showing everything from message.rs's wire layout test.
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
                block_number: Some(70_000_001),
                block_timestamp: Some(1_790_000_000),
                log_index: Some(7),
                quote: Some(vec![0x93, 1, 2, 3]),
            },
            first_seen: None,
        }
    }

    /// An entry for a listing that hides its time, with a made-up digest.
    fn hidden_entry() -> DigestEntry {
        DigestEntry {
            address: [0x33; 32],
            time: 1_789_999_200,
            block_number: 0,
            log_index: 0,
            first_seen: Some(1_789_999_200),
            digest: [0x44; 32],
        }
    }

    /// An entry with every field drawn from `seed`.
    fn entry(seed: u64) -> DigestEntry {
        let bytes = id(seed);
        let number = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
        DigestEntry {
            address: id(seed + 1_000_000),
            time: number(0) >> (number(8) % 64),
            block_number: number(8) >> (number(16) % 64),
            log_index: number(16) % 300,
            first_seen: seed.is_multiple_of(2).then(|| number(24) >> 20),
            digest: id(seed + 2_000_000),
        }
    }

    #[test]
    fn digest_entries_carry_the_key_first_seen_and_digest() {
        let listing = shown();
        let entry = DigestEntry::new(&listing);
        assert_eq!(entry.address, listing.address);
        assert_eq!(entry.key(), listing.key());
        assert_eq!(entry.first_seen, None);
        assert_eq!(entry.digest, listing.digest());
        assert!(entry.describes(&listing));

        // The wire bytes, as postcard writes them: the key's numbers as
        // varints, then first_seen and the digest.
        let expected = decode_hex(concat!(
            "1111111111111111111111111111111111111111111111111111111111111111",
            "80f7c4d506", // time
            "81bbb021",   // block number
            "07",         // log index
            "00",         // no first_seen
            "ff7382a741884769cfe1ed0093aaff1fe383981a87b6cd3e04128a6eb1d0a087",
        ))
        .unwrap();
        assert_eq!(entry.wire_bytes(), expected);
        assert_eq!(postcard::to_stdvec(&entry).unwrap(), expected);

        // A copy dated otherwise, or differing elsewhere, isn't described.
        let mut dated = listing.clone();
        dated.flags.shown = dated.flags.shown.without(PaymentField::BlockTimestamp);
        dated.payment.block_timestamp = None;
        dated.first_seen = Some(1_789_999_200);
        let dated_entry = DigestEntry::new(&dated);
        assert_eq!(dated_entry.time, 1_789_999_200);
        assert_eq!(dated_entry.first_seen, Some(1_789_999_200));
        assert!(dated_entry.describes(&dated));
        let mut later = dated.clone();
        later.first_seen = Some(1_789_999_200 + 3_600);
        assert_eq!(later.digest(), dated.digest());
        assert!(!dated_entry.describes(&later));
        let mut renamed = listing.clone();
        renamed.metadata.name = Some("b.txt".into());
        assert!(!entry.describes(&renamed));
        // An entry whose key doesn't fit its listing describes nothing.
        let mut moved = entry;
        moved.log_index += 1;
        assert!(!moved.describes(&listing));
    }

    #[test]
    fn entry_wire_bytes_are_postcards() {
        let largest = DigestEntry {
            address: [0xff; 32],
            time: u64::MAX,
            block_number: u64::MAX,
            log_index: u64::MAX,
            first_seen: Some(u64::MAX),
            digest: [0xff; 32],
        };
        for entry in (0..2_000).map(entry).chain([largest, hidden_entry()]) {
            assert_eq!(entry.wire_bytes(), postcard::to_stdvec(&entry).unwrap());
        }
    }

    #[test]
    fn set_hashes_are_sums_of_blake3() {
        // Worked out with an implementation of BLAKE3 apart from this
        // crate's.
        let shown = DigestEntry::new(&shown());
        let hidden = hidden_entry();
        let of_shown = hex32("19c9d6e39b3939e2b26c4b216f03c40c919efa73b49d7c17390086d224503d53");
        let of_hidden = hex32("c1b0c45f99b2befe4701e36411ff85c6e4bd195e2042276813280025e41dea40");
        let of_both = hex32("da799b4335ecf7e0fa6d2e8680024ad3755c14d2d4dfa37f4c2886f7086e2794");
        assert_eq!(SetHash::of_entry(&shown).to_bytes(), of_shown);
        assert_eq!(SetHash::of_entry(&hidden).to_bytes(), of_hidden);
        assert_eq!(SetHash::of([&shown, &hidden]).to_bytes(), of_both);
        assert_eq!(SetHash::of([&hidden, &shown]).to_bytes(), of_both);
        assert_eq!(SetHash::of([]), SetHash::EMPTY);
        assert_eq!(SetHash::EMPTY.to_bytes(), [0; 32]);
        assert_eq!(SetHash::default(), SetHash::EMPTY);

        let mut set = SetHash::EMPTY;
        set.insert(&shown);
        set.insert(&hidden);
        assert_eq!(set.to_bytes(), of_both);
        set.remove(&shown);
        assert_eq!(set.to_bytes(), of_hidden);
        set.remove(&hidden);
        assert_eq!(set, SetHash::EMPTY);

        // Modulo 2^256, little-endian: carries run up the bytes and off the
        // top, and borrows come back round.
        let all_ones = SetHash::from_bytes([0xff; 32]);
        let mut one = [0; 32];
        one[0] = 1;
        let one = SetHash::from_bytes(one);
        assert_eq!(all_ones + one, SetHash::EMPTY);
        assert_eq!(SetHash::EMPTY - one, all_ones);
        let mut low = [0; 32];
        low[0] = 0xff;
        let mut carried = [0; 32];
        carried[1] = 1;
        assert_eq!(SetHash::from_bytes(low) + one, SetHash::from_bytes(carried));

        // An entry counted twice doesn't cancel out, as it would by XOR.
        let twice = SetHash::of([&shown, &shown]);
        assert_ne!(twice, SetHash::EMPTY);
        assert_eq!(twice, SetHash::of_entry(&shown) + SetHash::of_entry(&shown));
        assert_eq!(
            format!("{:?}", SetHash::from_bytes([0xab; 32])),
            format!("SetHash({})", "ab".repeat(32))
        );
    }

    #[test]
    fn set_hashes_ignore_order_and_follow_inserts_and_removals() {
        let entries: Vec<DigestEntry> = (0..300).map(entry).collect();
        let whole = SetHash::of(&entries);
        let mut reversed = SetHash::EMPTY;
        for entry in entries.iter().rev() {
            reversed.insert(entry);
        }
        assert_eq!(reversed, whole);
        // Interleaved inserts and removals end at the remaining set's hash.
        let mut held = SetHash::EMPTY;
        for (n, entry) in entries.iter().enumerate() {
            held.insert(entry);
            if n % 3 == 0 {
                held.remove(&entries[n / 2]);
                held.insert(&entries[n / 2]);
            }
            if n % 5 == 4 {
                held.remove(entry);
            }
        }
        let kept = entries
            .iter()
            .enumerate()
            .filter(|(n, _)| n % 5 != 4)
            .map(|(_, entry)| entry);
        assert_eq!(held, SetHash::of(kept));
        // Any change to an entry changes its part.
        let base = hidden_entry();
        let mut variants = vec![base];
        for field in 0..6 {
            let mut other = base;
            match field {
                0 => other.address[0] ^= 1,
                1 => other.time += 1,
                2 => other.block_number += 1,
                3 => other.log_index += 1,
                4 => other.first_seen = None,
                _ => other.digest[31] ^= 1,
            }
            variants.push(other);
        }
        let parts: HashSet<SetHash> = variants.iter().map(SetHash::of_entry).collect();
        assert_eq!(parts.len(), variants.len());
    }

    #[test]
    fn set_hashes_add_up_over_prefixes() {
        // As a node keeps them: one per 16-bit prefix, added up for a range.
        let entries: Vec<DigestEntry> = (0..3_000)
            .map(|n| {
                let mut entry = entry(n);
                // Crowd them into a few prefixes, so each holds several.
                entry.address[0] = entry.address[0] % 4 + 0x60;
                entry.address[1] %= 16;
                entry
            })
            .collect();
        let mut by_prefix: BTreeMap<[u8; 2], SetHash> = BTreeMap::new();
        for entry in &entries {
            by_prefix
                .entry([entry.address[0], entry.address[1]])
                .or_default()
                .insert(entry);
        }
        for (prefix, bits) in [
            ([0x00; 32], 0),
            ([0x60; 32], 6),
            ([0x61; 32], 8),
            ([0x62; 32], 11),
            ([0x63; 32], 16),
            ([0x80; 32], 1),
        ] {
            let range = AddressRange::new(prefix, bits);
            let summed: SetHash = by_prefix
                .iter()
                .filter(|(prefix, _)| {
                    let mut address = [0; 32];
                    address[..2].copy_from_slice(prefix.as_slice());
                    range.contains(&address)
                })
                .map(|(_, hash)| *hash)
                .sum();
            let direct = SetHash::of(
                entries
                    .iter()
                    .filter(|entry| range.contains(&entry.address)),
            );
            assert_eq!(summed, direct, "{range:?}");
        }
        // They subtract too: the prefixes from 0x62 on are the total less
        // those before.
        let total: SetHash = by_prefix.values().copied().sum();
        let before: SetHash = by_prefix
            .iter()
            .filter(|(prefix, _)| prefix[0] < 0x62)
            .map(|(_, hash)| *hash)
            .sum();
        assert_eq!(
            total - before,
            SetHash::of(entries.iter().filter(|entry| entry.address[0] >= 0x62))
        );
    }

    #[test]
    fn set_hashes_travel_as_their_32_bytes() {
        let hash = SetHash::of([&hidden_entry()]);
        let bytes = postcard::to_stdvec(&hash).unwrap();
        assert_eq!(bytes, hash.to_bytes());
        assert_eq!(postcard::from_bytes::<SetHash>(&bytes).unwrap(), hash);
        assert_eq!(SetHash::from_bytes(hash.to_bytes()), hash);
    }

    #[test]
    fn view_hashes_ignore_order_and_repeats() {
        // Worked out with an implementation of BLAKE3 apart from this
        // crate's: BLAKE3 of 01..01 02..02 03..03.
        let expected = hex32("3656bd82356d3713799cc02c514eaa850ee36da8d8ab68d464022427d2619126");
        assert_eq!(view_hash(&[[3; 32], [1; 32], [2; 32], [1; 32]]), expected);
        assert_eq!(view_hash(&[[1; 32], [2; 32], [3; 32]]), expected);
        assert_ne!(view_hash(&[[1; 32], [2; 32]]), expected);
        // No peers: BLAKE3 of nothing.
        assert_eq!(
            view_hash(&[]),
            hex32("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
    }

    #[test]
    fn feed_changes_name_their_address_and_number() {
        let entry = hidden_entry();
        let listed = FeedChange::Entry { seq: 9, entry };
        assert_eq!(
            (listed.seq(), listed.address(), listed.entry()),
            (9, entry.address, Some(&entry))
        );
        let removed = FeedChange::Removed {
            seq: 10,
            address: [5; 32],
        };
        assert_eq!(
            (removed.seq(), removed.address(), removed.entry()),
            (10, [5; 32], None)
        );
    }

    #[test]
    fn address_ranges() {
        let all = AddressRange::ALL;
        assert_eq!((all.prefix(), all.bits()), ([0; 32], 0));
        assert!(all.contains(&[0; 32]) && all.contains(&[0xff; 32]));
        assert_eq!((all.first(), all.last()), ([0; 32], [0xff; 32]));

        // Bits after the prefix's are cleared.
        let range = AddressRange::new([0xab; 32], 12);
        let mut prefix = [0; 32];
        prefix[..2].copy_from_slice(&[0xab, 0xa0]);
        assert_eq!(range.prefix(), prefix);
        assert_eq!(range, AddressRange::new(prefix, 12));
        let mut last = [0xff; 32];
        last[..2].copy_from_slice(&[0xab, 0xaf]);
        assert_eq!((range.first(), range.last()), (prefix, last));
        assert!(range.contains(&prefix) && range.contains(&last));
        let mut below = prefix;
        below[1] = 0x9f;
        let mut above = last;
        above[1] = 0xb0;
        assert!(!range.contains(&below) && !range.contains(&above));

        let (lower, upper) = range.halves().unwrap();
        assert_eq!((lower.bits(), upper.bits()), (13, 13));
        assert_eq!(lower.first(), range.first());
        assert_eq!(upper.last(), range.last());
        assert_eq!(lower.last()[1], 0xa7);
        assert_eq!(upper.first()[1], 0xa8);
        assert!(range.covers(&lower) && range.covers(&upper) && range.covers(&range));
        assert!(!lower.covers(&range) && !lower.covers(&upper));
        assert!(all.covers(&range) && !range.covers(&all));

        // Byte boundaries, and the narrowest range there is.
        for bits in [7, 8, 9, 16, 254, 255] {
            let range = AddressRange::new([0x5a; 32], bits);
            assert!(range.contains(&[0x5a; 32]));
            assert!(range.contains(&range.first()) && range.contains(&range.last()));
            assert_eq!(range.halves().is_none(), bits == 255);
        }
        let narrowest = AddressRange::new([0x5a; 32], 255);
        let mut neighbour = [0x5a; 32];
        neighbour[31] ^= 1;
        assert!(narrowest.contains(&neighbour));
        neighbour[31] ^= 2;
        assert!(!narrowest.contains(&neighbour));

        // Every address is in exactly one half.
        for seed in 0..200 {
            let address = id(seed);
            let range = AddressRange::new(address, u8::try_from(seed % 40).unwrap());
            assert!(range.contains(&address));
            let (lower, upper) = range.halves().unwrap();
            assert!(lower.contains(&address) != upper.contains(&address));
        }
    }

    #[test]
    fn leaves_hold_the_nearest_nodes_to_every_address_in_them() {
        for (count, seed) in [
            (0, 1),
            (1, 2),
            (6, 3),
            (7, 4),
            (13, 5),
            (14, 6),
            (24, 7),
            (200, 8),
        ] {
            let ids: Vec<[u8; 32]> = (0..count).map(|n| id(seed * 10_000 + n)).collect();
            let tiled = leaves(&ids);
            // In address order, covering the space without gaps.
            assert_eq!(tiled[0].range.first(), [0; 32]);
            assert_eq!(tiled[tiled.len() - 1].range.last(), [0xff; 32]);
            for pair in tiled.windows(2) {
                let mut after = pair[0].range.last();
                for byte in after.iter_mut().rev() {
                    let (next, carried) = byte.overflowing_add(1);
                    *byte = next;
                    if !carried {
                        break;
                    }
                }
                assert_eq!(pair[1].range.first(), after);
            }
            // Every node in exactly one leaf, its own.
            let mut seen = vec![0; ids.len()];
            for leaf in &tiled {
                for &node in &leaf.nodes {
                    seen[node] += 1;
                    assert!(leaf.range.contains(&ids[node]));
                }
                // At least seven, unless there are fewer in all, and not
                // split further while both halves would hold seven.
                assert!(leaf.nodes.len() >= NEAREST_NODES.min(ids.len()));
                if let Some((lower, upper)) = leaf.range.halves() {
                    let held = |half: &AddressRange| {
                        leaf.nodes
                            .iter()
                            .filter(|&&node| half.contains(&ids[node]))
                            .count()
                    };
                    assert!(held(&lower) < NEAREST_NODES || held(&upper) < NEAREST_NODES);
                }
            }
            assert!(seen.iter().all(|&times| times == 1));
            // The seven nearest any address are in its leaf.
            for target in 0..300 {
                let address = id(seed * 77_777 + target);
                let leaf = &tiled[leaf_index(&tiled, &address).unwrap()];
                assert!(leaf.range.contains(&address));
                for node in nearest_by_distance(&address, &ids, NEAREST_NODES) {
                    assert!(leaf.nodes.contains(&node), "{count} nodes");
                }
            }
            if ids.len() >= 4 * NEAREST_NODES {
                assert!(tiled.len() > 1);
            }
        }
    }

    #[test]
    fn leaves_split_while_both_halves_hold_seven() {
        // Seven ids starting with a 0 bit and seven with a 1: one split, at
        // the top.
        let mut ids: Vec<[u8; 32]> = (0..14).map(id).collect();
        for (n, id) in ids.iter_mut().enumerate() {
            id[0] = if n < 7 { id[0] & 0x7f } else { id[0] | 0x80 };
        }
        let tiled = leaves(&ids);
        assert_eq!(tiled.len(), 2);
        assert_eq!(tiled[0].range, AddressRange::new([0; 32], 1));
        assert_eq!(tiled[1].range, AddressRange::new([0x80; 32], 1));
        assert_eq!(tiled[0].nodes, (0..7).collect::<Vec<_>>());
        assert_eq!(tiled[1].nodes, (7..14).collect::<Vec<_>>());
        // One fewer on one side: no split at all.
        let tiled = leaves(&ids[1..]);
        assert_eq!(tiled.len(), 1);
        assert_eq!(tiled[0].range, AddressRange::ALL);
        assert_eq!(tiled[0].nodes.len(), 13);
        // An id given twice counts twice: twenty of one id are one leaf.
        let same = vec![[0x42; 32]; 20];
        let tiled = leaves(&same);
        assert_eq!(tiled.len(), 1);
        assert_eq!(tiled[0].nodes.len(), 20);
        // Seven of an id, and seven more for each bit, differing from it
        // only there: every level splits, down to the narrowest range,
        // which holds the id and its neighbour in the last bit.
        let base = [0x42; 32];
        let mut ids = vec![base; NEAREST_NODES];
        for bit in 0..256 {
            let mut other = base;
            other[bit / 8] ^= 0x80 >> (bit % 8);
            ids.extend(vec![other; NEAREST_NODES]);
        }
        let tiled = leaves(&ids);
        assert_eq!(tiled.len(), 256);
        let narrowest = &tiled[leaf_index(&tiled, &base).unwrap()];
        assert_eq!(narrowest.range.bits(), 255);
        assert_eq!(narrowest.nodes.len(), 2 * NEAREST_NODES);
        let mut neighbour = base;
        neighbour[31] ^= 1;
        assert_eq!(leaf_index(&tiled, &base), leaf_index(&tiled, &neighbour));
        assert!(tiled.iter().all(|leaf| leaf.nodes.len() >= NEAREST_NODES));
        assert_eq!(leaf_index(&[], &[0; 32]), None);
    }
}
