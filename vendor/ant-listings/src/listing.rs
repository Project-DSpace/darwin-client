//! Listings: what a node records for each envelope it stores.
//!
//! A node finds the full [`Payment`] for an envelope when a client stores it,
//! then records [`Listing::new`]: only the payment fields the envelope's flags
//! show, and, for a listing in the index that hides the block timestamp, the
//! hour it was first seen. Hidden fields are never recorded, since a node
//! answers anyone who asks.
//!
//! Records written by version 1 of this crate read as [`ListingV1`] and
//! convert to [`Listing`].

use crate::envelope::{Envelope, EnvelopeError, Metadata};
use crate::flags::{Flags, PaymentField, ShownFields};
use crate::payment::{canonical_quote, ListingCheck, PaymentError};
use ant_protocol::XorName;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;
use thiserror::Error;

/// `first_seen` is rounded down to a multiple of this many seconds: an hour.
pub const FIRST_SEEN_ROUNDING: u64 = 3_600;

/// How far, in seconds, two clocks are allowed to disagree: a node's and the
/// chain's block timestamps, or a node's and a checker's. An hour. A node
/// records a listing only after its payment is in a block, so `first_seen`
/// can't be more than this before the hour of that block's timestamp (see
/// [`Listing::latest_payment_time`]), and no listing's time can be more than
/// this after the checker's clock (see [`Listing::check_not_in_future`]).
pub const CLOCK_MARGIN: u64 = 3_600;

/// Length of [`ListingKey::to_bytes`].
pub const LISTING_KEY_LEN: usize = 56;

/// `now`, in Unix seconds, rounded down to the hour: what a listing records
/// as `first_seen`.
#[must_use]
pub const fn first_seen_at(now: u64) -> u64 {
    now - now % FIRST_SEEN_ROUNDING
}

/// One file with an envelope, and the payment fields its uploader chose to
/// show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// The address of the envelope chunk, which is the file's address.
    pub address: XorName,
    /// The envelope's flags: the fields shown, whether the listing is in the
    /// index, and whether the data map is withheld.
    pub flags: Flags,
    /// The envelope's metadata.
    pub metadata: Metadata,
    /// The file's size in bytes, when the envelope's data map gives it
    /// directly. Always `None` when the data map is withheld.
    pub size: Option<u64>,
    /// The payment for the envelope chunk: the shown fields only.
    pub payment: ListingPayment,
    /// When the listing was first stored, in Unix seconds rounded down to the
    /// hour. Present exactly when the listing is in the index and hides the
    /// block timestamp, so the index can sort it without the exact time. Each
    /// node records its own; copies that differ only here are the same
    /// listing (see [`merge_copies`]).
    pub first_seen: Option<u64>,
}

/// The payment fields a listing shows. A field is `Some` exactly when the
/// listing's flags show it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingPayment {
    /// The payment transaction.
    pub tx_hash: Option<[u8; 32]>,
    /// The block the transaction is in.
    pub block_number: Option<u64>,
    /// The block's timestamp, in Unix seconds.
    pub block_timestamp: Option<u64>,
    /// The position in the block of the vault's `DataPaymentMade` event for
    /// the envelope chunk.
    pub log_index: Option<u64>,
    /// The paid quote, msgpack-encoded as in payment proofs but with its
    /// timestamp truncated to whole seconds, which is all its signature and
    /// hash cover, so each quote has one encoding. It names the envelope's
    /// address and is signed by the key it carries.
    pub quote: Option<Vec<u8>>,
}

impl ListingPayment {
    /// The fields present.
    #[must_use]
    pub fn present(&self) -> ShownFields {
        let present = [
            (PaymentField::TxHash, self.tx_hash.is_some()),
            (PaymentField::BlockNumber, self.block_number.is_some()),
            (PaymentField::BlockTimestamp, self.block_timestamp.is_some()),
            (PaymentField::LogIndex, self.log_index.is_some()),
            (PaymentField::Quote, self.quote.is_some()),
        ];
        present
            .into_iter()
            .filter(|(_, present)| *present)
            .map(|(field, _)| field)
            .collect()
    }
}

/// The full payment for an envelope chunk, as found on chain: what a node
/// checks at upload and a proof proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payment {
    /// The payment transaction.
    pub tx_hash: [u8; 32],
    /// The block the transaction is in.
    pub block_number: u64,
    /// The block's timestamp, in Unix seconds.
    pub block_timestamp: u64,
    /// The position in the block of the vault's `DataPaymentMade` event for
    /// the envelope chunk.
    pub log_index: u64,
    /// The paid quote, msgpack-encoded as in payment proofs, with its
    /// timestamp truncated to whole seconds (see [`ListingPayment::quote`]).
    pub quote: Vec<u8>,
}

impl Payment {
    /// The fields of this payment that `shown` shows.
    #[must_use]
    pub fn mask(&self, shown: ShownFields) -> ListingPayment {
        let show = |field| shown.contains(field);
        ListingPayment {
            tx_hash: show(PaymentField::TxHash).then_some(self.tx_hash),
            block_number: show(PaymentField::BlockNumber).then_some(self.block_number),
            block_timestamp: show(PaymentField::BlockTimestamp).then_some(self.block_timestamp),
            log_index: show(PaymentField::LogIndex).then_some(self.log_index),
            quote: show(PaymentField::Quote).then(|| self.quote.clone()),
        }
    }
}

/// Why a listing's fields don't fit its flags.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ListingError {
    /// The listing carries a field its flags hide.
    #[error("the listing carries the hidden field {0}")]
    HiddenFieldPresent(PaymentField),
    /// The listing lacks a field its flags show.
    #[error("the listing lacks the shown field {0}")]
    ShownFieldMissing(PaymentField),
    /// A listing in the index that hides the block timestamp has no
    /// `first_seen`.
    #[error("the listing has no first_seen")]
    MissingFirstSeen,
    /// A listing outside the index, or one that shows the block timestamp,
    /// has a `first_seen`.
    #[error("the listing has a first_seen it should not have")]
    UnexpectedFirstSeen,
    /// `first_seen` is not on the hour.
    #[error("first_seen is not rounded down to the hour")]
    FirstSeenNotRounded,
    /// `first_seen` or the shown block timestamp is later than the checker's
    /// clock allows (see [`Listing::check_not_in_future`]): a node dated the
    /// listing in the future, or recorded it with its clock in milliseconds.
    /// Also given if the checker's own clock runs more than [`CLOCK_MARGIN`]
    /// slow.
    #[error("the listing's time is in the future")]
    TimeInFuture,
    /// The listing doesn't describe the envelope at its address: the
    /// address, flags, metadata or size differ (see [`Listing::matches`]).
    #[error("the listing does not match its envelope")]
    EnvelopeMismatch,
    /// A listing whose data map is withheld has a size.
    #[error("the listing withholds its data map but has a size")]
    SizeWithoutDataMap,
    /// The metadata breaks a format rule.
    #[error("invalid metadata: {0}")]
    InvalidMetadata(EnvelopeError),
}

impl Listing {
    /// The listing a node records for `envelope`, paid by `payment` (as
    /// [`find_payment`](crate::find_payment) found it), stored at `now` (Unix
    /// seconds). Keeps only the shown fields, and sets `first_seen` when the
    /// listing is in the index and hides the block timestamp.
    ///
    /// `first_seen` is the hour of `now`, or of the payment's block if that is
    /// later: no node stores a listing before its payment, so a node whose
    /// clock runs slow still records a `first_seen` that checks out.
    #[must_use]
    pub fn new(envelope: &Envelope, payment: &Payment, now: u64) -> Self {
        let flags = envelope.flags();
        Self {
            address: envelope.address(),
            flags,
            metadata: envelope.metadata().clone(),
            size: envelope.file_size(),
            payment: payment.mask(flags.shown),
            first_seen: needs_first_seen(flags)
                .then(|| first_seen_at(now.max(payment.block_timestamp))),
        }
    }

    /// Check that the fields fit the flags: exactly the shown payment fields,
    /// `first_seen` exactly when needed and on the hour, no size when the data
    /// map is withheld, and valid metadata. [`verify_listing`] does this
    /// first; a node can do it on any listing it receives.
    ///
    /// The name is checked under version 2's rule, unless the flags are
    /// [`Flags::V1`]: a version 1 envelope always reads as those, so such a
    /// listing may describe one, and its name is checked under version 1's
    /// rule, which allows every name version 2 does and more. Any other
    /// flags can only come from a version 2 envelope. [`verify_listing`]
    /// still holds a listing to its envelope's own rule, since the listing
    /// must match the envelope, which only parses if its metadata follows its
    /// version's rules.
    ///
    /// [`verify_listing`]: crate::verify_listing
    ///
    /// # Errors
    ///
    /// Returns the first problem found.
    pub fn validate(&self) -> Result<(), ListingError> {
        let present = self.payment.present();
        for field in PaymentField::ALL {
            match (self.flags.shown.contains(field), present.contains(field)) {
                (false, true) => return Err(ListingError::HiddenFieldPresent(field)),
                (true, false) => return Err(ListingError::ShownFieldMissing(field)),
                _ => {}
            }
        }
        match (needs_first_seen(self.flags), self.first_seen) {
            (true, None) => return Err(ListingError::MissingFirstSeen),
            (false, Some(_)) => return Err(ListingError::UnexpectedFirstSeen),
            (true, Some(first_seen)) if first_seen % FIRST_SEEN_ROUNDING != 0 => {
                return Err(ListingError::FirstSeenNotRounded)
            }
            _ => {}
        }
        if self.flags.withheld && self.size.is_some() {
            return Err(ListingError::SizeWithoutDataMap);
        }
        if self.flags == Flags::V1 {
            self.metadata.validate_any_version()
        } else {
            self.metadata.validate()
        }
        .map_err(ListingError::InvalidMetadata)
    }

    /// Check that the listing's time is not in the future: neither
    /// `first_seen` nor a shown block timestamp is later than `now` (Unix
    /// seconds, by the checker's clock) plus [`CLOCK_MARGIN`]. For
    /// `first_seen`, which is on the hour, that is the hour of `now` plus
    /// [`CLOCK_MARGIN`]. Either is the listing's time in the index
    /// ([`key`](Self::key)), so a node could otherwise pin a listing to the
    /// top of a newest-first index, or date an old one now. [`verify_listing`]
    /// does this; a node can do it on any listing it receives.
    ///
    /// The chain also checks a shown block timestamp wherever the payment's
    /// block is located. Where nothing locates it, this is its only check.
    ///
    /// [`verify_listing`]: crate::verify_listing
    ///
    /// # Errors
    ///
    /// Returns [`ListingError::TimeInFuture`].
    pub fn check_not_in_future(&self, now: u64) -> Result<(), ListingError> {
        let latest = now.saturating_add(CLOCK_MARGIN);
        let times = [self.first_seen, self.payment.block_timestamp];
        if times.into_iter().flatten().any(|time| time > latest) {
            return Err(ListingError::TimeInFuture);
        }
        Ok(())
    }

    /// The listing's place in the index. Listings outside the index can be
    /// given a key too, but nothing sorts them.
    #[must_use]
    pub fn key(&self) -> ListingKey {
        ListingKey {
            time: self
                .payment
                .block_timestamp
                .or(self.first_seen)
                .unwrap_or(0),
            block_number: self.payment.block_number.unwrap_or(0),
            log_index: self.payment.log_index.unwrap_or(0),
            address: self.address,
        }
    }

    /// The latest block timestamp, in Unix seconds, that the listing's payment
    /// can have, when it has `first_seen`: `first_seen` plus
    /// [`FIRST_SEEN_ROUNDING`] plus [`CLOCK_MARGIN`]. A node records a listing
    /// only once its payment is in a block, so a payment in a later block
    /// means `first_seen` was set too early. `None` without `first_seen`.
    #[must_use]
    pub fn latest_payment_time(&self) -> Option<u64> {
        self.first_seen
            .map(|first_seen| first_seen.saturating_add(FIRST_SEEN_ROUNDING + CLOCK_MARGIN))
    }

    /// Whether this listing describes `envelope`: the same address, flags,
    /// metadata and size.
    #[must_use]
    pub fn matches(&self, envelope: &Envelope) -> bool {
        self.address == envelope.address()
            && self.flags == envelope.flags()
            && &self.metadata == envelope.metadata()
            && self.size == envelope.file_size()
    }

    /// Whether two listings are the same apart from `first_seen`, which each
    /// node records for itself: for merging copies from several nodes, and
    /// for counting agreeing answers on repair.
    #[must_use]
    pub fn eq_apart_from_first_seen(&self, other: &Self) -> bool {
        let Self {
            address,
            flags,
            metadata,
            size,
            payment,
            first_seen: _,
        } = self;
        *address == other.address
            && *flags == other.flags
            && *metadata == other.metadata
            && *size == other.size
            && *payment == other.payment
    }
}

fn needs_first_seen(flags: Flags) -> bool {
    flags.in_index && !flags.shown.contains(PaymentField::BlockTimestamp)
}

/// A listing as version 1 of this crate recorded it, for reading records
/// stored before version 2: every payment field present, and no flags or
/// `first_seen`. Version 1 envelopes are all shown, in the index and
/// readable, so [`Listing::from`] gives the version 2 listing a node records
/// for the same envelope and payment.
///
/// Its postcard encoding is version 1's, field for field, so a record stored
/// as `postcard(Listing)` by version 1 decodes as this type. It must never
/// change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingV1 {
    /// The address of the envelope chunk.
    pub address: XorName,
    /// The envelope's metadata.
    pub metadata: Metadata,
    /// The file's size in bytes, when the data map gives it directly.
    pub size: Option<u64>,
    /// The payment for the envelope chunk.
    pub payment: PaymentV1,
}

/// The payment in a [`ListingV1`]: all five fields, in version 1's order.
/// [`Payment::from`] truncates the quote's timestamp to whole seconds, as
/// version 2 records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentV1 {
    /// The payment transaction.
    pub tx_hash: [u8; 32],
    /// The block the transaction is in.
    pub block_number: u64,
    /// The block's timestamp, in Unix seconds.
    pub block_timestamp: u64,
    /// The position in the block of the vault's `DataPaymentMade` event for
    /// the envelope chunk.
    pub log_index: u64,
    /// The paid quote, msgpack-encoded as in payment proofs.
    pub quote: Vec<u8>,
}

impl From<PaymentV1> for Payment {
    fn from(old: PaymentV1) -> Self {
        Self {
            tx_hash: old.tx_hash,
            block_number: old.block_number,
            block_timestamp: old.block_timestamp,
            log_index: old.log_index,
            quote: canonical_quote(old.quote),
        }
    }
}

impl From<ListingV1> for Listing {
    fn from(old: ListingV1) -> Self {
        let payment = Payment::from(old.payment);
        Self {
            address: old.address,
            flags: Flags::V1,
            metadata: old.metadata,
            size: old.size,
            payment: payment.mask(ShownFields::ALL),
            first_seen: None,
        }
    }
}

/// The median of copies' `first_seen` values: the middle one, or the later of
/// the two middle ones for an even count, so moving it earlier, which would
/// date a listing before it was stored, takes more than half the values. It
/// is always one of the values, so still on the hour. `None` for no values.
#[must_use]
pub fn median_first_seen(values: impl IntoIterator<Item = u64>) -> Option<u64> {
    let mut values: Vec<u64> = values.into_iter().collect();
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

/// One listing, merged from the copies of it that peers returned. Its own
/// fields are those the copies agree on; take the listing itself, with its
/// `first_seen`, from [`checked_listing_among`](Self::checked_listing_among)
/// the nodes nearest its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedListing<P> {
    /// The listing with `first_seen` left out (`None`): each peer's value is
    /// in `peers`. Private, since without its `first_seen` a listing that
    /// needs one fails [`Listing::validate`] and sorts at time 0.
    listing: Listing,
    /// The peers that returned it, each once, in the order their copies came
    /// in, with the `first_seen` each returned.
    peers: Vec<(P, Option<u64>)>,
}

impl<P> MergedListing<P> {
    /// The file's address.
    #[must_use]
    pub fn address(&self) -> XorName {
        self.listing.address
    }

    /// The envelope's flags, as the copies give them.
    #[must_use]
    pub fn flags(&self) -> Flags {
        self.listing.flags
    }

    /// The envelope's metadata, as the copies give it.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.listing.metadata
    }

    /// The file's size, as the copies give it.
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.listing.size
    }

    /// The shown payment fields, as the copies give them.
    #[must_use]
    pub fn payment(&self) -> &ListingPayment {
        &self.listing.payment
    }

    /// The peers that returned this listing, each once, in the order their
    /// copies came in, with the `first_seen` each returned.
    #[must_use]
    pub fn peers(&self) -> &[(P, Option<u64>)] {
        &self.peers
    }

    /// The listing's time, for deciding whether a walk of a peer's index
    /// came after the peer stored it: the shown block timestamp, or the
    /// latest `first_seen` any peer returned. A peer that sends a later one
    /// only makes walks count less.
    fn latest_time(&self) -> Option<u64> {
        self.listing
            .payment
            .block_timestamp
            .or_else(|| self.peers.iter().filter_map(|(_, value)| *value).max())
    }
}

impl<P: PartialEq> MergedListing<P> {
    /// How many of `nearest` returned this listing: for a
    /// [`CheckLevel::Reported`](crate::CheckLevel::Reported) listing, `n` of
    /// the nodes nearest its address, to compare with
    /// [`quorum_needed`](crate::quorum_needed); for verified listings, see
    /// [`choose_verified`](crate::choose_verified).
    ///
    /// Only peers whose copies were merged count. A node never asked is not
    /// a node that doesn't serve the listing: ask the ones
    /// [`unheard_among`](Self::unheard_among) gives before deciding.
    #[must_use]
    pub fn count_among(&self, nearest: &[P]) -> usize {
        self.peers
            .iter()
            .filter(|(peer, _)| nearest.contains(peer))
            .count()
    }

    /// The peers of `nearest` still to ask for this listing's address (a
    /// `GetRequest`) before deciding on it: those that didn't return it and
    /// haven't otherwise answered for its address.
    ///
    /// - `heard(peer)` is true for a peer that answered a `GetRequest` for
    ///   the address, or returned another copy for it.
    /// - `walked(peer)` gives when (Unix seconds) a walk of the peer's whole
    ///   index began, if one ran to the end. A walk counts as an answer only
    ///   for a listing in the index, since list requests never return the
    ///   others, and only if it began at least [`FIRST_SEEN_ROUNDING`] plus
    ///   [`CLOCK_MARGIN`] after the listing's time (its shown block
    ///   timestamp, or the latest `first_seen` any peer returned): a walk
    ///   that began earlier may have passed the listing's place before the
    ///   peer stored it. A listing that shows its time and was stored more
    ///   than that after its payment can still be missed that way; a
    ///   `GetRequest` settles it.
    #[must_use]
    pub fn unheard_among<'a>(
        &self,
        nearest: &'a [P],
        heard: impl Fn(&P) -> bool,
        walked: impl Fn(&P) -> Option<u64>,
    ) -> Vec<&'a P> {
        let walk_after = self
            .listing
            .flags
            .in_index
            .then(|| self.latest_time())
            .flatten()
            .map(|time| time.saturating_add(FIRST_SEEN_ROUNDING + CLOCK_MARGIN));
        let walked_since = |peer: &P| {
            walk_after.is_some_and(|after| walked(peer).is_some_and(|began| began >= after))
        };
        nearest
            .iter()
            .filter(|peer| {
                !heard(peer)
                    && !walked_since(peer)
                    && !self.peers.iter().any(|(other, _)| other == *peer)
            })
            .collect()
    }

    /// The listing, with `first_seen` the [`median_first_seen`] of the values
    /// that the peers in `nearest` returned, and no others: peers outside the
    /// nearest nodes can't move it, however many they are. `None` if the
    /// listing needs a `first_seen` and none of `nearest` returned it. A
    /// listing without one is returned whoever served it.
    ///
    /// The values are not checked, so one out of bounds moves the median
    /// and can fail the listing: use it to know what to fetch
    /// ([`payment_lookup`](crate::payment_lookup)), then check the listing
    /// with [`checked_listing_among`](Self::checked_listing_among).
    ///
    /// For a repairing node, `nearest` is the close-group peers it asked; for
    /// an indexer, the nodes nearest the listing's address.
    #[must_use]
    pub fn listing_among(&self, nearest: &[P]) -> Option<Listing> {
        if !needs_first_seen(self.listing.flags) {
            return Some(self.listing.clone());
        }
        let first_seen = median_first_seen(self.first_seen_among(nearest))?;
        Some(self.with_first_seen(first_seen))
    }

    /// The listing, with `first_seen` set by the nodes nearest its address,
    /// and checked with `check`: typically
    /// [`verify_listing_receipts`](crate::verify_listing_receipts) over what
    /// the caller fetched for [`payment_lookup`](crate::payment_lookup) of
    /// [`listing_among`](Self::listing_among).
    ///
    /// For a listing that needs `first_seen`, each value a peer in `nearest`
    /// returned is checked on its own first, and the values that fail are
    /// dropped: one in the future, or one before the payment where the
    /// payment's block is known. So such a value neither fails the listing
    /// nor moves its `first_seen`, which is the [`median_first_seen`] of the
    /// values that pass, one per peer. A listing without `first_seen` is
    /// checked as it is, whoever served it.
    ///
    /// `check` is called once for each different value, so it must give the
    /// same answer for the same listing: check against what was fetched,
    /// rather than fetching again. For a repairing node, `nearest` is the
    /// close-group peers it asked; for an indexer, the nodes nearest the
    /// listing's address. Whether enough of them serve the listing is the
    /// caller's to decide ([`count_among`](Self::count_among)).
    ///
    /// # Errors
    ///
    /// For a listing that needs `first_seen`:
    /// [`ListingError::MissingFirstSeen`] if none of `nearest` returned it,
    /// and if no value passes, the error `check` gave for the median of them
    /// all. For any other listing, the error `check` gave for it.
    pub fn checked_listing_among(
        &self,
        nearest: &[P],
        mut check: impl FnMut(&Listing) -> Result<ListingCheck, PaymentError>,
    ) -> Result<(Listing, ListingCheck), PaymentError> {
        if !needs_first_seen(self.listing.flags) {
            let listing = self.listing.clone();
            let checked = check(&listing)?;
            return Ok((listing, checked));
        }
        let values: Vec<u64> = self.first_seen_among(nearest).collect();
        let mut distinct = values.clone();
        distinct.sort_unstable();
        distinct.dedup();
        let results: Vec<(u64, Result<ListingCheck, PaymentError>)> = distinct
            .into_iter()
            .map(|value| (value, check(&self.with_first_seen(value))))
            .collect();
        let result_for = |value: u64| {
            results
                .iter()
                .find(|(checked, _)| *checked == value)
                .map(|(_, result)| result)
        };
        let passed = values
            .iter()
            .copied()
            .filter(|&value| result_for(value).is_some_and(Result::is_ok));
        let chosen = median_first_seen(passed)
            .or_else(|| median_first_seen(values.iter().copied()))
            .ok_or(ListingError::MissingFirstSeen)?;
        match result_for(chosen) {
            Some(Ok(checked)) => Ok((self.with_first_seen(chosen), *checked)),
            Some(Err(error)) => Err(error.clone()),
            None => Err(ListingError::MissingFirstSeen.into()),
        }
    }

    /// The `first_seen` values the peers in `nearest` returned, one per peer.
    fn first_seen_among<'a>(&'a self, nearest: &'a [P]) -> impl Iterator<Item = u64> + 'a {
        self.peers
            .iter()
            .filter(|(peer, _)| nearest.contains(peer))
            .filter_map(|(_, first_seen)| *first_seen)
    }

    fn with_first_seen(&self, first_seen: u64) -> Listing {
        Listing {
            first_seen: Some(first_seen),
            ..self.listing.clone()
        }
    }
}

/// Merge the copies of listings that peers returned: copies equal apart from
/// `first_seen` are one listing, keeping each peer's `first_seen`. Listings
/// that differ otherwise, even for the same address, stay apart. Groups come
/// out in the order their first copy came in.
///
/// - A copy that fails [`Listing::validate`] is left out, so it neither
///   counts nor moves the median.
/// - A peer counts at most once for an address: a second copy equal to its
///   first is ignored.
/// - A peer that returned two different copies for an address, even ones
///   that differ only in `first_seen`, is left out for that address
///   altogether.
///
/// Take each group's listing from [`MergedListing::checked_listing_among`]
/// the nodes nearest its address, so that only they set its `first_seen`.
#[must_use]
pub fn merge_copies<P: Eq + Hash + Clone>(
    copies: impl IntoIterator<Item = (P, Listing)>,
) -> Vec<MergedListing<P>> {
    // One copy per peer and address, in the order they came in; `None` once
    // the peer has contradicted itself.
    let mut order: Vec<(XorName, P)> = Vec::new();
    let mut by_peer: HashMap<(XorName, P), Option<Listing>> = HashMap::new();
    for (peer, listing) in copies {
        if listing.validate().is_err() {
            continue;
        }
        match by_peer.entry((listing.address, peer)) {
            Entry::Vacant(entry) => {
                order.push(entry.key().clone());
                entry.insert(Some(listing));
            }
            Entry::Occupied(mut entry) => {
                if entry.get().as_ref() != Some(&listing) {
                    entry.insert(None);
                }
            }
        }
    }

    let mut groups: Vec<MergedListing<P>> = Vec::new();
    let mut by_address: HashMap<XorName, Vec<usize>> = HashMap::new();
    for key in order {
        let Some(Some(mut listing)) = by_peer.remove(&key) else {
            continue;
        };
        let (address, peer) = key;
        let first_seen = listing.first_seen.take();
        let candidates = by_address.entry(address).or_default();
        let found = candidates
            .iter()
            .copied()
            .find(|&group| groups[group].listing == listing);
        if let Some(group) = found {
            groups[group].peers.push((peer, first_seen));
        } else {
            candidates.push(groups.len());
            groups.push(MergedListing {
                listing,
                peers: vec![(peer, first_seen)],
            });
        }
    }
    groups
}

/// How many of `nearest` serve some listing for one address, given the groups
/// [`merge_copies`] made of its copies: each node once, whichever listing it
/// serves. Nodes outside `nearest` don't count, however many they are.
#[must_use]
pub fn support_among<P: PartialEq>(groups: &[MergedListing<P>], nearest: &[P]) -> usize {
    nearest
        .iter()
        .filter(|node| {
            groups
                .iter()
                .any(|group| group.peers.iter().any(|(peer, _)| peer == *node))
        })
        .count()
}

/// The listing at least `needed` of the nodes `nearest` its address serve as
/// `group`, unchecked, dated as the nodes date a listing their close group
/// serves: its `first_seen`, if it needs one, is the latest of the earliest
/// `needed` dates those nodes sent, so that a quorum of them date it then or
/// earlier. With all seven answering and a quorum of four that is their
/// median; with fewer, nodes fewer than a quorum still can't move it before
/// the earliest date another gives, nor later than the latest. `None` if
/// fewer than `needed` of `nearest` serve it.
///
/// For a repairing node, `nearest` is the close-group peers it asked and
/// `needed` is [`quorum_needed`](crate::quorum_needed) of how many; for an
/// indexer, the nodes nearest the address.
#[must_use]
pub fn quorum_listing<P: PartialEq>(
    group: &MergedListing<P>,
    nearest: &[P],
    needed: usize,
) -> Option<Listing> {
    if group.count_among(nearest) < needed {
        return None;
    }
    let mut listing = group.listing_among(nearest)?;
    if listing.first_seen.is_some() {
        let mut dates: Vec<u64> = group.first_seen_among(nearest).collect();
        dates.sort_unstable();
        listing.first_seen = Some(*dates.get(needed.checked_sub(1)?)?);
    }
    Some(listing)
}

/// The listing to look up on chain for `group` (and to show for it if it
/// fails): [`quorum_listing`] when at least `needed` of `nearest` serve it,
/// otherwise [`MergedListing::listing_among`] (the median of their dates).
/// `None` if it needs a `first_seen` and none of `nearest` sent one.
#[must_use]
pub fn listing_to_check<P: PartialEq>(
    group: &MergedListing<P>,
    nearest: &[P],
    needed: usize,
) -> Option<Listing> {
    if group.count_among(nearest) >= needed {
        quorum_listing(group, nearest, needed)
    } else {
        group.listing_among(nearest)
    }
}

/// Check `group`, the copies of one listing, against what was fetched for
/// [`listing_to_check`]: as a node checks its close group's copies when it
/// repairs a listing, and as an indexer checks the copies the nodes nearest
/// an address serve. Only the dates of `nearest` count:
///
/// - a group at least `needed` of them serve is dated as [`quorum_listing`]
///   dates it, over the dates that pass their own check: a date in the
///   future, or before the payment, is dropped first, so one node can't fail
///   a listing a quorum serves by sending one. If fewer than `needed` dates
///   pass, the group is checked as below. Where every date passes, this is
///   [`quorum_listing`]'s date;
/// - any other group is checked with
///   [`MergedListing::checked_listing_among`]: each date on its own, those
///   that fail dropped, and the median of the rest.
///
/// `check` is typically [`verify_listing_receipts`](crate::verify_listing_receipts)
/// over what was fetched. It is called once for each different date, so it
/// must give the same answer for the same listing.
///
/// # Errors
///
/// The error `check` gives for the listing, or
/// [`ListingError::MissingFirstSeen`] if it needs a date that too few of
/// `nearest` sent.
pub fn check_copies<P: PartialEq>(
    group: &MergedListing<P>,
    nearest: &[P],
    needed: usize,
    mut check: impl FnMut(&Listing) -> Result<ListingCheck, PaymentError>,
) -> Result<(Listing, ListingCheck), PaymentError> {
    if group.count_among(nearest) < needed || !needs_first_seen(group.listing.flags) {
        return group.checked_listing_among(nearest, check);
    }
    let mut dates: Vec<u64> = group.first_seen_among(nearest).collect();
    dates.sort_unstable();
    let mut results: Vec<(u64, Result<ListingCheck, PaymentError>)> = Vec::new();
    for &date in &dates {
        if !results.iter().any(|(checked, _)| *checked == date) {
            results.push((date, check(&group.with_first_seen(date))));
        }
    }
    let result_for = |date: u64| {
        results
            .iter()
            .find(|(checked, _)| *checked == date)
            .map(|(_, result)| result.clone())
    };
    let passing: Vec<u64> = dates
        .iter()
        .copied()
        .filter(|&date| result_for(date).is_some_and(|result| result.is_ok()))
        .collect();
    if let Some(&date) = needed.checked_sub(1).and_then(|index| passing.get(index)) {
        if let Some(Ok(checked)) = result_for(date) {
            return Ok((group.with_first_seen(date), checked));
        }
    }
    group.checked_listing_among(nearest, |listing| {
        listing
            .first_seen
            .and_then(result_for)
            .unwrap_or_else(|| check(listing))
    })
}

/// Where a listing sits in the index: by time, then block number, log index
/// and address. The time is the block timestamp if shown, otherwise
/// `first_seen`, otherwise 0; a hidden block number or log index counts as 0.
///
/// For listings that show all five fields this is the order their payments
/// were made in. The derived order is the order of [`to_bytes`](Self::to_bytes).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ListingKey {
    /// The block timestamp, or `first_seen`, in Unix seconds.
    pub time: u64,
    /// The payment's block.
    pub block_number: u64,
    /// The payment event's position in the block.
    pub log_index: u64,
    /// The file's address, which breaks the remaining ties.
    pub address: XorName,
}

impl ListingKey {
    /// The first key: list requests from it return everything.
    pub const MIN: Self = Self {
        time: 0,
        block_number: 0,
        log_index: 0,
        address: [0; 32],
    };

    /// The key as bytes whose order is the key order, for a byte-ordered store
    /// such as LMDB: time, block number and log index as 8 bytes big-endian
    /// each, then the 32-byte address.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; LISTING_KEY_LEN] {
        let mut bytes = [0u8; LISTING_KEY_LEN];
        bytes[..8].copy_from_slice(&self.time.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.block_number.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.log_index.to_be_bytes());
        bytes[24..].copy_from_slice(&self.address);
        bytes
    }

    /// Read [`to_bytes`](Self::to_bytes) back. `None` unless `bytes` is
    /// exactly [`LISTING_KEY_LEN`] long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (time, rest) = bytes.split_first_chunk::<8>()?;
        let (block_number, rest) = rest.split_first_chunk::<8>()?;
        let (log_index, rest) = rest.split_first_chunk::<8>()?;
        Some(Self {
            time: u64::from_be_bytes(*time),
            block_number: u64::from_be_bytes(*block_number),
            log_index: u64::from_be_bytes(*log_index),
            address: rest.try_into().ok()?,
        })
    }

    /// The smallest key after this one, or `None` for the largest key. For
    /// paging through listings: ask for the next page from the last key
    /// received, `checked_next()`, and stop at `None`. See also
    /// [`check_list_page`](crate::check_list_page).
    #[must_use]
    pub fn checked_next(self) -> Option<Self> {
        let mut bytes = self.to_bytes();
        for byte in bytes.iter_mut().rev() {
            if let Some(incremented) = byte.checked_add(1) {
                *byte = incremented;
                return Self::from_bytes(&bytes);
            }
            *byte = 0;
        }
        None
    }

    /// [`checked_next`](Self::checked_next), but the largest key gives
    /// itself. Paging with it never ends on a page whose last key is the
    /// largest: use `checked_next` for paging.
    #[must_use]
    pub fn next(self) -> Self {
        self.checked_next().unwrap_or(self)
    }

    /// Where to walk a node's index from to find the listings it stored
    /// since a walk of it began at `walk_began` (Unix seconds, by the
    /// walker's clock). `put_delay` is the longest time, in seconds, between
    /// a payment and the PUT of its envelope that the walker wants to catch.
    ///
    /// Keys are payment times, not the times nodes stored the listings, so a
    /// listing stored after a walk passed its place has a key before where
    /// the walk stopped, and walking on from the last key seen misses it:
    ///
    /// - one that hides its time is keyed by the hour it was stored, by the
    ///   node's clock: up to [`FIRST_SEEN_ROUNDING`] plus [`CLOCK_MARGIN`]
    ///   before the walker's clock said it was;
    /// - one that shows its time is keyed by its block time, however late
    ///   its PUT came: up to [`CLOCK_MARGIN`] plus the PUT's delay before.
    ///
    /// So the next walk starts at `walk_began` less all three (saturating),
    /// and drops listings it has already seen. A listing repaired onto a node
    /// keeps its key however old: other nodes stored it first, so it is
    /// found there, and only a walk from [`ListingKey::MIN`] finds every
    /// copy.
    #[must_use]
    pub fn since(walk_began: u64, put_delay: u64) -> Self {
        let lookback = (FIRST_SEEN_ROUNDING + CLOCK_MARGIN).saturating_add(put_delay);
        Self {
            time: walk_began.saturating_sub(lookback),
            ..Self::MIN
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Salt;
    use crate::test_support::{data_map, metadata};

    const SALT: Salt = [9; 32];
    const NOW: u64 = 1_790_001_234;

    fn full_payment() -> Payment {
        Payment {
            tx_hash: [7; 32],
            block_number: 42,
            block_timestamp: 1_790_000_000,
            log_index: 3,
            quote: vec![1, 2, 3],
        }
    }

    fn envelope(shown: ShownFields, in_index: bool, withheld: bool) -> Envelope {
        let map = data_map(&[10, 20, 30]);
        let meta = metadata(Some("text/plain"), Some("a.txt"));
        if withheld {
            Envelope::withheld(&map, &SALT, meta, shown, in_index).unwrap()
        } else {
            Envelope::readable(&map, meta, shown, in_index).unwrap()
        }
    }

    fn key(time: u64, block_number: u64, log_index: u64, last: u8) -> ListingKey {
        let mut address = [0; 32];
        address[31] = last;
        ListingKey {
            time,
            block_number,
            log_index,
            address,
        }
    }

    #[test]
    fn masks_every_shown_set() {
        let payment = full_payment();
        for shown in ShownFields::every() {
            for in_index in [false, true] {
                for withheld in [false, true] {
                    let envelope = envelope(shown, in_index, withheld);
                    let listing = Listing::new(&envelope, &payment, NOW);
                    assert_eq!(listing.validate(), Ok(()), "{shown:?}");
                    assert!(listing.matches(&envelope));
                    assert_eq!(listing.address, envelope.address());
                    assert_eq!(listing.flags, envelope.flags());
                    assert_eq!(listing.size, (!withheld).then_some(60));
                    assert_eq!(listing.payment.present(), shown);

                    let p = &listing.payment;
                    let show = |field| shown.contains(field);
                    assert_eq!(p.tx_hash, show(PaymentField::TxHash).then_some([7; 32]));
                    assert_eq!(
                        p.block_number,
                        show(PaymentField::BlockNumber).then_some(42)
                    );
                    assert_eq!(
                        p.block_timestamp,
                        show(PaymentField::BlockTimestamp).then_some(1_790_000_000)
                    );
                    assert_eq!(p.log_index, show(PaymentField::LogIndex).then_some(3));
                    assert_eq!(p.quote, show(PaymentField::Quote).then(|| vec![1, 2, 3]));

                    let hides_time = !show(PaymentField::BlockTimestamp);
                    let first_seen = (in_index && hides_time).then_some(1_789_999_200);
                    assert_eq!(listing.first_seen, first_seen);

                    let key = listing.key();
                    let time = if hides_time {
                        first_seen.unwrap_or(0)
                    } else {
                        1_790_000_000
                    };
                    assert_eq!(key.time, time);
                    assert_eq!(
                        key.block_number,
                        if show(PaymentField::BlockNumber) {
                            42
                        } else {
                            0
                        }
                    );
                    assert_eq!(
                        key.log_index,
                        if show(PaymentField::LogIndex) { 3 } else { 0 }
                    );
                    assert_eq!(key.address, listing.address);

                    let encoded = postcard::to_stdvec(&listing).unwrap();
                    assert_eq!(postcard::from_bytes::<Listing>(&encoded).unwrap(), listing);
                }
            }
        }
    }

    #[test]
    fn version_1_envelopes_list_as_before() {
        let map = data_map(&[10, 20, 30]);
        let mut bytes = b"\0ANTLIST\x01\x00\x00".to_vec();
        bytes.extend_from_slice(&rmp_serde::to_vec(&map).unwrap());
        let envelope = Envelope::from_bytes(&bytes).unwrap();
        let listing = Listing::new(&envelope, &full_payment(), NOW);
        assert_eq!(listing.flags, Flags::V1);
        assert_eq!(listing.payment.present(), ShownFields::ALL);
        assert_eq!(listing.first_seen, None);
        assert_eq!(
            listing.key(),
            ListingKey {
                time: 1_790_000_000,
                block_number: 42,
                log_index: 3,
                address: envelope.address(),
            }
        );
    }

    #[test]
    fn first_seen_is_rounded_down_to_the_hour() {
        for (now, expected) in [
            (0, 0),
            (1, 0),
            (3_599, 0),
            (3_600, 3_600),
            (3_601, 3_600),
            (7_199, 3_600),
            (1_790_001_234, 1_789_999_200),
            (u64::MAX, u64::MAX - u64::MAX % 3_600),
        ] {
            assert_eq!(first_seen_at(now), expected, "{now}");
            assert_eq!(first_seen_at(now) % FIRST_SEEN_ROUNDING, 0);
            assert!(first_seen_at(now) <= now && now - first_seen_at(now) < 3_600);
        }
        let shown = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        let paid_at_start = Payment {
            block_timestamp: 0,
            ..full_payment()
        };
        let listing = Listing::new(&envelope(shown, true, false), &paid_at_start, 7_199);
        assert_eq!(listing.first_seen, Some(3_600));
    }

    #[test]
    fn a_slow_clock_dates_a_listing_at_its_payment() {
        let paid_at = full_payment().block_timestamp;
        let shown = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        let env = envelope(shown, true, false);
        // A node whose clock is hours behind the chain's records the hour of
        // the payment's block, not an hour before it.
        for now in [0, paid_at - 5 * 3_600, paid_at - 1, paid_at] {
            let listing = Listing::new(&env, &full_payment(), now);
            assert_eq!(listing.first_seen, Some(first_seen_at(paid_at)), "{now}");
            assert!(listing.latest_payment_time().unwrap() >= paid_at);
        }
        // Later, its own clock's hour.
        let listing = Listing::new(&env, &full_payment(), paid_at + 7_200);
        assert_eq!(listing.first_seen, Some(first_seen_at(paid_at + 7_200)));
    }

    #[test]
    fn first_seen_cannot_be_in_the_future() {
        let shown = ShownFields::NONE;
        let listing = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        let first_seen = listing.first_seen.unwrap();
        let with_first_seen = |first_seen| Listing {
            first_seen: Some(first_seen),
            ..listing.clone()
        };
        // Checked at the time it was recorded, or any time after.
        for now in [NOW, first_seen, NOW + 86_400, u64::MAX] {
            assert_eq!(listing.check_not_in_future(now), Ok(()), "{now}");
        }
        // A checker whose clock is up to CLOCK_MARGIN behind still takes it.
        assert_eq!(
            listing.check_not_in_future(first_seen - CLOCK_MARGIN),
            Ok(())
        );
        let ahead = with_first_seen(first_seen + CLOCK_MARGIN);
        assert_eq!(ahead.check_not_in_future(first_seen), Ok(()));
        // On the hour, the bound is the hour of the checker's clock plus
        // CLOCK_MARGIN, at any second of that hour.
        for now in [first_seen, first_seen + 1, first_seen + 3_599] {
            assert_eq!(ahead.check_not_in_future(now), Ok(()), "{now}");
        }
        // More than that is in the future.
        let future = Err(ListingError::TimeInFuture);
        assert_eq!(
            listing.check_not_in_future(first_seen - CLOCK_MARGIN - 1),
            future
        );
        for too_late in [
            first_seen + CLOCK_MARGIN + FIRST_SEEN_ROUNDING,
            first_seen_at(4_102_444_800),
            first_seen_at(u64::MAX / 2),
            first_seen_at(u64::MAX),
        ] {
            let moved = with_first_seen(too_late);
            assert_eq!(moved.validate(), Ok(()));
            assert_eq!(moved.check_not_in_future(NOW), future, "{too_late}");
        }
        // A node that passed its clock in milliseconds.
        let millis = Listing::new(&envelope(shown, true, false), &full_payment(), NOW * 1_000);
        assert_eq!(millis.validate(), Ok(()));
        assert_eq!(millis.check_not_in_future(NOW), future);
        // Listings without first_seen check their shown block timestamp.
        let timed = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        let paid_at = full_payment().block_timestamp;
        assert_eq!(timed.check_not_in_future(paid_at - CLOCK_MARGIN), Ok(()));
        assert_eq!(
            timed.check_not_in_future(paid_at - CLOCK_MARGIN - 1),
            future
        );
        // Hidden, it has nothing to check.
        let hidden = Listing::new(&envelope(shown, false, false), &full_payment(), NOW);
        assert_eq!(hidden.first_seen, None);
        assert_eq!(hidden.check_not_in_future(0), Ok(()));
    }

    #[test]
    fn a_shown_timestamp_cannot_be_in_the_future() {
        // Only the timestamp shown, in the index: nothing locates the
        // payment, so this bound is the only check on the listing's time.
        let shown = ShownFields::NONE.with(PaymentField::BlockTimestamp);
        let listing = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        assert_eq!(listing.first_seen, None);
        assert_eq!(listing.check_not_in_future(NOW), Ok(()));
        for pinned in [NOW + CLOCK_MARGIN + 1, 4_102_444_800, u64::MAX] {
            let mut moved = listing.clone();
            moved.payment.block_timestamp = Some(pinned);
            assert_eq!(moved.validate(), Ok(()));
            assert_eq!(moved.key().time, pinned);
            assert_eq!(
                moved.check_not_in_future(NOW),
                Err(ListingError::TimeInFuture),
                "{pinned}"
            );
        }
        let mut edge = listing;
        edge.payment.block_timestamp = Some(NOW + CLOCK_MARGIN);
        assert_eq!(edge.check_not_in_future(NOW), Ok(()));
    }

    #[test]
    fn validate_rejects_fields_that_do_not_fit_the_flags() {
        let shown = ShownFields::NONE.with(PaymentField::TxHash);
        let good = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        assert_eq!(good.validate(), Ok(()));

        let mut hidden = good.clone();
        hidden.payment.quote = Some(vec![1]);
        assert_eq!(
            hidden.validate(),
            Err(ListingError::HiddenFieldPresent(PaymentField::Quote))
        );
        let mut missing = good.clone();
        missing.payment.tx_hash = None;
        assert_eq!(
            missing.validate(),
            Err(ListingError::ShownFieldMissing(PaymentField::TxHash))
        );
        let mut no_first_seen = good.clone();
        no_first_seen.first_seen = None;
        assert_eq!(
            no_first_seen.validate(),
            Err(ListingError::MissingFirstSeen)
        );
        let mut unrounded = good.clone();
        unrounded.first_seen = Some(NOW);
        assert_eq!(unrounded.validate(), Err(ListingError::FirstSeenNotRounded));
        let mut outside = good.clone();
        outside.flags.in_index = false;
        assert_eq!(outside.validate(), Err(ListingError::UnexpectedFirstSeen));
        let mut timed = good.clone();
        timed.flags.shown = shown.with(PaymentField::BlockTimestamp);
        timed.payment.block_timestamp = Some(1);
        assert_eq!(timed.validate(), Err(ListingError::UnexpectedFirstSeen));
        let mut sized = good.clone();
        sized.flags.withheld = true;
        assert_eq!(sized.validate(), Err(ListingError::SizeWithoutDataMap));
        let mut bad_name = good.clone();
        bad_name.metadata.name = Some("a/b".into());
        assert!(matches!(
            bad_name.validate(),
            Err(ListingError::InvalidMetadata(_))
        ));
        // Names only version 1 allows: valid only with the flags a version 1
        // envelope reads as, all shown and in the index with its data map.
        // Any other flags come from a version 2 envelope, whose rule refuses
        // them. The listing must still match its envelope.
        let v1 = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        assert_eq!(v1.flags, Flags::V1);
        for name in [
            ".",
            "..",
            "a\u{FF0F}b",
            "a\u{2216}b",
            "zero\u{200B}width",
            "invoice\u{202E}fdp.exe",
        ] {
            assert!(metadata(None, Some(name)).validate().is_err(), "{name:?}");
            let mut old_name = v1.clone();
            old_name.metadata.name = Some(name.into());
            assert_eq!(old_name.validate(), Ok(()), "{name:?}");
            let mut new_name = good.clone();
            new_name.metadata.name = Some(name.into());
            assert!(
                matches!(new_name.validate(), Err(ListingError::InvalidMetadata(_))),
                "{name:?}"
            );
        }
        // Withheld and in the index, hiding everything (0x60): it can only
        // come from a version 2 envelope, so a right-to-left override in its
        // name is refused before anyone shows it.
        let mut dated = Listing::new(
            &envelope(ShownFields::NONE, true, true),
            &full_payment(),
            NOW,
        );
        assert_eq!(dated.flags.to_byte(), 0x60);
        assert_eq!(dated.validate(), Ok(()));
        dated.metadata.name = Some("invoice\u{202E}fdp.exe".into());
        assert_eq!(
            dated.validate(),
            Err(ListingError::InvalidMetadata(EnvelopeError::InvalidName(
                "must not contain invisible format or line separator characters"
            )))
        );
        assert!(merge_copies([(1, dated.clone())]).is_empty());
    }

    #[test]
    fn listings_match_only_their_envelope() {
        let env = envelope(ShownFields::ALL, true, false);
        let listing = Listing::new(&env, &full_payment(), NOW);
        assert!(listing.matches(&env));
        for other in [
            envelope(ShownFields::ALL, false, false),
            envelope(ShownFields::NONE, true, false),
            envelope(ShownFields::ALL, true, true),
        ] {
            assert!(!listing.matches(&other));
        }
        let mut moved = listing.clone();
        moved.size = Some(1);
        assert!(!moved.matches(&env));
        let mut renamed = listing;
        renamed.metadata.name = None;
        assert!(!renamed.matches(&env));
    }

    #[test]
    fn equality_apart_from_first_seen() {
        let shown = ShownFields::NONE;
        let a = Listing::new(&envelope(shown, true, true), &full_payment(), NOW);
        let mut b = a.clone();
        b.first_seen = Some(0);
        assert_ne!(a, b);
        assert!(a.eq_apart_from_first_seen(&b));
        let mut c = a.clone();
        c.metadata.name = None;
        assert!(!a.eq_apart_from_first_seen(&c));
        let mut d = a.clone();
        d.flags.in_index = false;
        assert!(!a.eq_apart_from_first_seen(&d));
        let mut e = a.clone();
        e.payment.log_index = Some(1);
        assert!(!a.eq_apart_from_first_seen(&e));
        let mut f = a.clone();
        f.address[0] ^= 1;
        assert!(!a.eq_apart_from_first_seen(&f));
    }

    #[test]
    fn medians() {
        assert_eq!(median_first_seen([]), None);
        assert_eq!(median_first_seen([7_200]), Some(7_200));
        // The later of two middle values: moving it earlier takes more
        // than half the values.
        assert_eq!(median_first_seen([7_200, 3_600]), Some(7_200));
        assert_eq!(median_first_seen([0, 0, 7_200, 7_200]), Some(7_200));
        assert_eq!(median_first_seen([0, 0, 0, 7_200]), Some(0));
        assert_eq!(median_first_seen([10_800, 3_600, 7_200]), Some(7_200));
        assert_eq!(median_first_seen([0, 0, 7_200]), Some(0));
        assert_eq!(
            median_first_seen([0, 3_600, 3_600, 360_000, 7_200, 7_200, 7_200]),
            Some(7_200)
        );
    }

    #[test]
    fn merges_copies_equal_apart_from_first_seen() {
        let shown = ShownFields::NONE;
        let base = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        let with_first_seen = |first_seen| Listing {
            first_seen: Some(first_seen),
            ..base.clone()
        };
        let mut changed = with_first_seen(3_600);
        changed.metadata.name = Some("b.txt".into());
        let other = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );

        let merged = merge_copies([
            ("a", with_first_seen(10_800)),
            ("b", with_first_seen(3_600)),
            ("c", changed.clone()),
            ("d", with_first_seen(7_200)),
            ("a", other.clone()),
            ("e", with_first_seen(7_200)),
        ]);
        assert_eq!(merged.len(), 3);
        assert_eq!(peers(&merged[0]), ["a", "b", "d", "e"]);
        assert_eq!(
            merged[0].peers(),
            [
                ("a", Some(10_800)),
                ("b", Some(3_600)),
                ("d", Some(7_200)),
                ("e", Some(7_200))
            ]
        );
        // The merged listing leaves first_seen to listing_among, and shows
        // what the copies agree on.
        assert_eq!(merged[0].listing.first_seen, None);
        assert_eq!(merged[0].address(), base.address);
        assert_eq!(merged[0].flags(), base.flags);
        assert_eq!(merged[0].metadata(), &base.metadata);
        assert_eq!(merged[0].size(), base.size);
        assert_eq!(merged[0].payment(), &base.payment);
        let all = ["a", "b", "c", "d", "e"];
        assert_eq!(merged[0].listing_among(&all), Some(with_first_seen(7_200)));
        assert_eq!(peers(&merged[1]), ["c"]);
        assert_eq!(merged[1].listing_among(&all), Some(changed));
        assert_eq!(peers(&merged[2]), ["a"]);
        assert_eq!(merged[2].listing_among(&[]), Some(other.clone()));
        assert!(merge_copies::<u8>([]).is_empty());

        let nearest = ["b", "d", "x", "e", "y", "z", "w"];
        assert_eq!(merged[0].count_among(&nearest), 3);
        assert_eq!(merged[1].count_among(&nearest), 0);
        assert_eq!(merged[0].count_among(&[]), 0);
        // Only the nearest set the median: b, d and e, not a.
        assert_eq!(
            merged[0].listing_among(&nearest),
            Some(with_first_seen(7_200))
        );
        assert_eq!(
            merged[0].listing_among(&["a", "b"]),
            Some(with_first_seen(10_800))
        );
        assert_eq!(
            merged[0].listing_among(&["a"]),
            Some(with_first_seen(10_800))
        );
        // None of the nearest returned it, so nothing sets its first_seen.
        assert_eq!(merged[1].listing_among(&nearest), None);
        // A listing without first_seen needs none of them.
        assert_eq!(merged[2].listing_among(&nearest), Some(other.clone()));
        assert_eq!(merged[2].listing_among(&[]), Some(other));
    }

    /// The peers of a merged listing, without their first_seen values.
    fn peers<P: Clone>(merged: &MergedListing<P>) -> Vec<P> {
        merged
            .peers()
            .iter()
            .map(|(peer, _)| peer.clone())
            .collect()
    }

    #[test]
    fn only_the_nearest_set_first_seen() {
        let shown = ShownFields::NONE;
        let honest = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        let with_first_seen = |first_seen| Listing {
            first_seen: Some(first_seen),
            ..honest.clone()
        };
        let nearest: Vec<String> = (0..7).map(|i| format!("near{i}")).collect();
        let far_future = first_seen_at(4_102_444_800);
        for outsider_value in [far_future, 0] {
            // The 7 nearest agree; 8 peers outside them, more than the
            // nearest, send another first_seen.
            let mut copies: Vec<(String, Listing)> = nearest
                .iter()
                .map(|peer| (peer.clone(), honest.clone()))
                .collect();
            copies.extend((0..8).map(|i| (format!("other{i}"), with_first_seen(outsider_value))));
            let merged = merge_copies(copies);
            assert_eq!(merged.len(), 1);
            assert_eq!(merged[0].peers().len(), 15);
            assert_eq!(merged[0].count_among(&nearest), 7);
            assert_eq!(merged[0].listing_among(&nearest), Some(honest.clone()));
        }

        // A minority of the nearest can't move it either.
        let mut copies: Vec<(String, Listing)> = nearest[..4]
            .iter()
            .map(|peer| (peer.clone(), honest.clone()))
            .collect();
        copies.extend(
            nearest[4..]
                .iter()
                .map(|peer| (peer.clone(), with_first_seen(far_future))),
        );
        let merged = merge_copies(copies);
        assert_eq!(merged[0].listing_among(&nearest), Some(honest.clone()));
    }

    #[test]
    fn unheard_peers_are_asked_before_deciding() {
        let shown = ShownFields::NONE;
        let listing = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        let first_seen = listing.first_seen.unwrap();
        let mut renamed = listing.clone();
        renamed.metadata.name = Some("b.txt".into());
        let merged = merge_copies([(1, listing.clone()), (2, listing.clone()), (3, renamed)]);
        let nearest = [1, 2, 3, 4, 5, 6, 7];
        let unwalked = |_: &u8| None;
        // 2 of 7 served it: short of the 4 needed, but only 3 have been heard.
        assert_eq!(merged[0].count_among(&nearest), 2);
        let heard = |peer: &u8| [1, 2, 3].contains(peer);
        assert_eq!(
            merged[0].unheard_among(&nearest, heard, unwalked),
            [&4, &5, &6, &7]
        );
        // Peers that answered without it, or with another copy, are heard.
        let heard = |peer: &u8| [1, 2, 3, 4, 5].contains(peer);
        assert_eq!(merged[0].unheard_among(&nearest, heard, unwalked), [&6, &7]);
        assert_eq!(merged[1].unheard_among(&nearest, heard, unwalked), [&6, &7]);
        // A peer that served it is never unheard.
        assert_eq!(
            merged[0].unheard_among(&nearest, |_| false, unwalked),
            [&3, &4, &5, &6, &7]
        );
        assert!(merged[0]
            .unheard_among(&nearest, |_| true, unwalked)
            .is_empty());

        // A walk of a peer's whole index answers for a listing in the index,
        // once it began late enough that the peer had stored the listing.
        let settled = first_seen + FIRST_SEEN_ROUNDING + CLOCK_MARGIN;
        let walked = |peer: &u8| match peer {
            4 => Some(settled),
            5 => Some(settled - 1),
            6 => Some(u64::MAX),
            _ => None,
        };
        assert_eq!(
            merged[0].unheard_among(&nearest, |peer| *peer == 3, walked),
            [&5, &7]
        );
        // A peer that sends a later first_seen only makes walks count less.
        let mut late = listing.clone();
        late.first_seen = Some(first_seen + 10 * FIRST_SEEN_ROUNDING);
        let merged = merge_copies([(1, listing.clone()), (8, late)]);
        assert_eq!(
            merged[0].unheard_among(&nearest, |_| false, walked),
            [&2, &3, &4, &5, &7]
        );

        // A walk never answers for a listing outside the index, which list
        // requests never return, however late it began.
        let outside = Listing::new(&envelope(shown, false, false), &full_payment(), NOW);
        let merged = merge_copies([(1, outside.clone()), (2, outside)]);
        assert_eq!(
            merged[0].unheard_among(&nearest, |_| false, |_| Some(u64::MAX)),
            [&3, &4, &5, &6, &7]
        );
        assert_eq!(
            merged[0].unheard_among(&nearest, |peer| *peer > 2, |_| Some(u64::MAX)),
            Vec::<&u8>::new()
        );

        // A listing showing its time counts walks from its block time.
        let timed = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        let paid_at = full_payment().block_timestamp;
        let merged = merge_copies([(1, timed)]);
        let walked = |peer: &u8| match peer {
            2 => Some(paid_at + FIRST_SEEN_ROUNDING + CLOCK_MARGIN),
            3 => Some(paid_at),
            _ => None,
        };
        assert_eq!(
            merged[0].unheard_among(&nearest, |_| false, walked),
            [&3, &4, &5, &6, &7]
        );
    }

    #[test]
    fn checked_listings_drop_values_that_fail_on_their_own() {
        use crate::payment::{CheckLevel, ListingCheck, PaymentError};
        use std::cell::RefCell;

        let shown = ShownFields::NONE;
        let honest = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        let h = honest.first_seen.unwrap();
        let ok = ListingCheck {
            level: CheckLevel::Reported,
            paid_at: None,
        };
        // A check that takes first_seen between h - 1 hour and h + 1 hour,
        // and records what it was asked.
        let asked = RefCell::new(Vec::new());
        let check = |listing: &Listing| {
            let first_seen = listing.first_seen.unwrap();
            asked.borrow_mut().push(first_seen);
            if first_seen > h + 3_600 {
                Err(PaymentError::Malformed(ListingError::TimeInFuture))
            } else if first_seen + 3_600 < h {
                Err(PaymentError::FirstSeenTooEarly)
            } else {
                Ok(ok)
            }
        };
        let nearest = [1, 2, 3, 4, 5, 6, 7];
        let merged_with = |values: &[u64]| {
            let copies = (1..).zip(values).map(|(peer, &value)| {
                (
                    peer,
                    Listing {
                        first_seen: Some(value),
                        ..honest.clone()
                    },
                )
            });
            merge_copies(copies).remove(0)
        };
        let with_first_seen = |first_seen| Listing {
            first_seen: Some(first_seen),
            ..honest.clone()
        };

        // Half the values out of bounds, either way: dropped before the
        // median, which an unchecked median can't do.
        let far = h + 100 * 3_600;
        for values in [vec![0, 0, 0, h, h, h], vec![far, far, far, h, h, h]] {
            let merged = merged_with(&values);
            asked.borrow_mut().clear();
            assert_eq!(
                merged.checked_listing_among(&nearest, check),
                Ok((with_first_seen(h), ok))
            );
            // Each different value is checked once, and nothing more.
            let mut distinct = values.clone();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(*asked.borrow(), distinct);
        }
        assert_eq!(
            merged_with(&[far, far, far, h, h, h]).listing_among(&nearest),
            Some(with_first_seen(far))
        );
        // The median of the values that pass, one per peer.
        let merged = merged_with(&[h - 3_600, h, h + 3_600, h + 3_600, 0]);
        assert_eq!(
            merged.checked_listing_among(&nearest, check),
            Ok((with_first_seen(h + 3_600), ok))
        );
        // Only the nearest count.
        assert_eq!(
            merged.checked_listing_among(&[1, 2], check),
            Ok((with_first_seen(h), ok))
        );
        // None passes: the error the median of them all gives.
        assert_eq!(
            merged_with(&[0, 0, far]).checked_listing_among(&nearest, check),
            Err(PaymentError::FirstSeenTooEarly)
        );
        assert_eq!(
            merged_with(&[0, far, far]).checked_listing_among(&nearest, check),
            Err(PaymentError::Malformed(ListingError::TimeInFuture))
        );
        // None of the nearest returned it.
        assert_eq!(
            merged.checked_listing_among(&[8, 9], check),
            Err(PaymentError::Malformed(ListingError::MissingFirstSeen))
        );

        // A listing without first_seen is checked once, as it is.
        let timed = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        let merged = merge_copies([(9, timed.clone())]).remove(0);
        let mut calls = 0;
        let result = merged.checked_listing_among(&[], |listing| {
            calls += 1;
            assert_eq!(listing, &timed);
            Ok(ok)
        });
        assert_eq!((result, calls), (Ok((timed, ok)), 1));
        let failed = merged.checked_listing_among(&[], |_| Err(PaymentError::NotPaid));
        assert_eq!(failed, Err(PaymentError::NotPaid));
    }

    #[test]
    fn a_quorum_is_dated_over_the_dates_that_pass() {
        use crate::payment::{CheckLevel, ListingCheck, PaymentError};

        let honest = Listing::new(
            &envelope(ShownFields::NONE, true, false),
            &full_payment(),
            NOW,
        );
        let h = honest.first_seen.unwrap();
        let ok = ListingCheck {
            level: CheckLevel::Reported,
            paid_at: None,
        };
        let check = |listing: &Listing| {
            let first_seen = listing.first_seen.unwrap();
            if first_seen > h + 3_600 {
                Err(PaymentError::Malformed(ListingError::TimeInFuture))
            } else if first_seen + 3_600 < h {
                Err(PaymentError::FirstSeenTooEarly)
            } else {
                Ok(ok)
            }
        };
        let nearest = [1, 2, 3, 4, 5, 6, 7];
        let merged_with = |values: &[u64]| {
            let copies = (1..).zip(values).map(|(peer, &value)| {
                (
                    peer,
                    Listing {
                        first_seen: Some(value),
                        ..honest.clone()
                    },
                )
            });
            merge_copies(copies).remove(0)
        };
        let dated = |first_seen| Listing {
            first_seen: Some(first_seen),
            ..honest.clone()
        };
        let far = h + 100 * 3_600;

        // Three honest dates and one in the future, from four nodes: the
        // future one no longer fails the listing they serve.
        let merged = merged_with(&[h, h, h, far]);
        assert_eq!(quorum_listing(&merged, &nearest, 4), Some(dated(far)));
        assert_eq!(
            check_copies(&merged, &nearest, 4, check),
            Ok((dated(h), ok))
        );

        // Where every date passes, the date is quorum_listing's.
        for values in [
            vec![h, h, h, h],
            vec![h - 3_600, h, h, h + 3_600, h + 3_600],
            vec![h; 7],
        ] {
            let merged = merged_with(&values);
            let expected = quorum_listing(&merged, &nearest, 4).unwrap();
            assert_eq!(
                check_copies(&merged, &nearest, 4, check),
                Ok((expected, ok))
            );
        }

        // A date before the payment still can't move it earlier.
        let merged = merged_with(&[0, h, h, h, h + 3_600, h + 3_600, far]);
        assert_eq!(
            check_copies(&merged, &nearest, 4, check),
            Ok((dated(h + 3_600), ok))
        );

        // Fewer than a quorum of dates pass: the median of those that do.
        let merged = merged_with(&[h, h - 3_600, far, far]);
        assert_eq!(
            check_copies(&merged, &nearest, 4, check),
            Ok((dated(h), ok))
        );

        // None passes: the error the median of them all gives.
        assert_eq!(
            check_copies(&merged_with(&[far, far, far, far]), &nearest, 4, check),
            Err(PaymentError::Malformed(ListingError::TimeInFuture))
        );
    }

    #[test]
    fn support_counts_each_nearest_node_once_whatever_it_serves() {
        let honest = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        let mut other = honest.clone();
        other.payment.log_index = Some(9);
        let groups = merge_copies([
            (1, honest.clone()),
            (2, honest.clone()),
            (3, other),
            (8, honest),
        ]);
        assert_eq!(groups.len(), 2);
        assert_eq!(support_among(&groups, &[1, 2, 3, 4, 5, 6, 7]), 3);
        assert_eq!(support_among(&groups, &[8]), 1);
        assert_eq!(support_among(&groups, &[]), 0);
    }

    #[test]
    fn a_peer_counts_once_per_address() {
        let shown = ShownFields::NONE;
        let base = Listing::new(&envelope(shown, true, false), &full_payment(), NOW);
        let with_first_seen = |first_seen| Listing {
            first_seen: Some(first_seen),
            ..base.clone()
        };

        // The same copy twice from one peer counts once.
        let merged = merge_copies([
            (1, with_first_seen(3_600)),
            (1, with_first_seen(3_600)),
            (2, with_first_seen(7_200)),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(peers(&merged[0]), [1, 2]);
        assert_eq!(
            merged[0].listing_among(&[1, 2]),
            Some(with_first_seen(7_200))
        );
        assert_eq!(merged[0].listing_among(&[1]), Some(with_first_seen(3_600)));

        // A peer that sends one address several times with different
        // first_seen values can't fill a quorum alone: it doesn't count.
        let merged = merge_copies([
            (9, with_first_seen(0)),
            (9, with_first_seen(3_600)),
            (9, with_first_seen(7_200)),
            (9, with_first_seen(10_800)),
        ]);
        assert!(merged.is_empty());
        let merged = merge_copies([
            (9, with_first_seen(0)),
            (1, with_first_seen(7_200)),
            (9, with_first_seen(3_600)),
            (2, with_first_seen(7_200)),
            (9, with_first_seen(0)),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(peers(&merged[0]), [1, 2]);
        assert_eq!(
            merged[0].listing_among(&[1, 2, 9]),
            Some(with_first_seen(7_200))
        );

        // Nor does one that sends two different listings for an address,
        // in either group.
        let mut renamed = with_first_seen(7_200);
        renamed.metadata.name = Some("b.txt".into());
        let merged = merge_copies([
            (9, with_first_seen(7_200)),
            (1, with_first_seen(7_200)),
            (9, renamed.clone()),
            (2, renamed.clone()),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(peers(&merged[0]), [1]);
        assert_eq!(peers(&merged[1]), [2]);

        // Different addresses from one peer each count.
        let other = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        let merged = merge_copies([(9, with_first_seen(7_200)), (9, other)]);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(|group| peers(group) == [9]));
    }

    #[test]
    fn merging_leaves_out_malformed_copies() {
        // The timestamp is shown, so no copy may have first_seen.
        let timed = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        let mut bad = timed.clone();
        bad.first_seen = Some(1);
        let merged = merge_copies([
            (1, timed.clone()),
            (2, timed.clone()),
            (3, bad),
            (4, timed.clone()),
            (5, timed.clone()),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].listing, timed);
        assert_eq!(merged[0].listing_among(&[1]), Some(timed.clone()));
        assert_eq!(peers(&merged[0]), [1, 2, 4, 5]);

        // Hidden: an unrounded value would otherwise be the median of two,
        // and a missing one would count without a value.
        let hidden = ShownFields::NONE;
        let base = Listing::new(&envelope(hidden, true, false), &full_payment(), NOW);
        let mut unrounded = base.clone();
        unrounded.first_seen = Some(1);
        let mut missing = base.clone();
        missing.first_seen = None;
        let mut leaked = base.clone();
        leaked.payment.log_index = Some(3);
        let merged = merge_copies([(1, base.clone()), (2, unrounded), (3, missing), (4, leaked)]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].listing_among(&[1, 2, 3, 4]), Some(base.clone()));
        assert_eq!(peers(&merged[0]), [1]);

        // A malformed copy doesn't make its peer contradict itself.
        let mut garbled = base.clone();
        garbled.first_seen = Some(5);
        let merged = merge_copies([(1, garbled), (1, base.clone())]);
        assert_eq!(peers(&merged[0]), [1]);
    }

    #[test]
    fn version_1_records_convert() {
        // A record as version 1 stored it: postcard of its Listing, here one
        // paid in block 70,000,001 at log index 3.
        let address: XorName = [
            0x3a, 0x91, 0x0c, 0x5e, 0x77, 0x28, 0xb4, 0x16, 0xe2, 0x49, 0x8d, 0x03, 0xc5, 0x6f,
            0x1b, 0xa0, 0x52, 0xd8, 0x34, 0x9e, 0x0a, 0x67, 0xf1, 0x2c, 0x85, 0x4b, 0xe9, 0x13,
            0x70, 0xbd, 0x26, 0x58,
        ];
        let quote = [0x9c, 0xc4, 0x20, 0x01];
        for metadata in [
            Metadata::default(),
            metadata(Some("application/octet-stream"), Some("random.bin")),
        ] {
            let mut bytes = address.to_vec();
            for field in [&metadata.content_type, &metadata.name] {
                match field {
                    Some(field) => {
                        bytes.push(1);
                        bytes.push(u8::try_from(field.len()).unwrap());
                        bytes.extend_from_slice(field.as_bytes());
                    }
                    None => bytes.push(0),
                }
            }
            // size: Some(20480)
            bytes.extend_from_slice(&[0x01, 0x80, 0xa0, 0x01]);
            // tx hash
            bytes.extend_from_slice(&[0x7a; 32]);
            // block 70,000,001, timestamp 1,790,000,123, log index 3
            bytes.extend_from_slice(&[0x81, 0xbb, 0xb0, 0x21]);
            bytes.extend_from_slice(&[0xfb, 0xf7, 0xc4, 0xd5, 0x06]);
            bytes.push(0x03);
            // quote
            bytes.push(4);
            bytes.extend_from_slice(&quote);

            // A version 2 Listing can't read it.
            assert!(postcard::from_bytes::<Listing>(&bytes).is_err());

            let old: ListingV1 = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(postcard::to_stdvec(&old).unwrap(), bytes);
            assert_eq!(
                old,
                ListingV1 {
                    address,
                    metadata: metadata.clone(),
                    size: Some(20_480),
                    payment: PaymentV1 {
                        tx_hash: [0x7a; 32],
                        block_number: 70_000_001,
                        block_timestamp: 1_790_000_123,
                        log_index: 3,
                        quote: quote.to_vec(),
                    },
                }
            );

            let listing = Listing::from(old);
            assert_eq!(listing.validate(), Ok(()));
            assert_eq!(listing.flags, Flags::V1);
            assert_eq!(listing.metadata, metadata);
            assert_eq!(listing.size, Some(20_480));
            assert_eq!(listing.first_seen, None);
            assert_eq!(
                listing.payment,
                ListingPayment {
                    tx_hash: Some([0x7a; 32]),
                    block_number: Some(70_000_001),
                    block_timestamp: Some(1_790_000_123),
                    log_index: Some(3),
                    quote: Some(quote.to_vec()),
                }
            );
            assert_eq!(
                listing.key(),
                ListingKey {
                    time: 1_790_000_123,
                    block_number: 70_000_001,
                    log_index: 3,
                    address,
                }
            );
        }
    }

    #[test]
    fn version_1_records_with_version_1_names_stay_valid() {
        let shown_everything = full_payment();
        for name in [
            // 👨‍👩‍👧.jpg, می‌خواهم.txt and two names only version 1 allows.
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.jpg",
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}.txt",
            "..",
            "a\u{FF0F}b",
        ] {
            let old = ListingV1 {
                address: [5; 32],
                metadata: metadata(None, Some(name)),
                size: Some(6),
                payment: PaymentV1 {
                    tx_hash: shown_everything.tx_hash,
                    block_number: shown_everything.block_number,
                    block_timestamp: shown_everything.block_timestamp,
                    log_index: shown_everything.log_index,
                    quote: shown_everything.quote.clone(),
                },
            };
            let listing = Listing::from(old);
            assert_eq!(listing.validate(), Ok(()), "{name:?}");
            // Every node that carried it over still serves it, and it counts.
            let merged = merge_copies((0..7).map(|peer| (peer, listing.clone())));
            assert_eq!(merged.len(), 1, "{name:?}");
            assert_eq!(merged[0].count_among(&[0, 1, 2, 3, 4, 5, 6]), 7);
        }
    }

    #[test]
    fn version_1_records_give_what_a_node_records_now() {
        let map = data_map(&[10, 20, 30]);
        let meta = metadata(Some("text/plain"), Some("a.txt"));
        let mut bytes = b"\0ANTLIST\x01\x0atext/plain\x05a.txt".to_vec();
        bytes.extend_from_slice(&rmp_serde::to_vec(&map).unwrap());
        let envelope = Envelope::from_bytes(&bytes).unwrap();
        let payment = full_payment();
        let old = ListingV1 {
            address: envelope.address(),
            metadata: meta,
            size: envelope.file_size(),
            payment: PaymentV1 {
                tx_hash: payment.tx_hash,
                block_number: payment.block_number,
                block_timestamp: payment.block_timestamp,
                log_index: payment.log_index,
                quote: payment.quote.clone(),
            },
        };
        let listing = Listing::from(old);
        assert!(listing.matches(&envelope));
        assert_eq!(listing, Listing::new(&envelope, &payment, NOW));
    }

    #[test]
    fn the_latest_payment_time_follows_first_seen() {
        let hidden = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        let listing = Listing::new(&envelope(hidden, true, false), &full_payment(), NOW);
        assert_eq!(listing.first_seen, Some(1_789_999_200));
        assert_eq!(
            listing.latest_payment_time(),
            Some(1_789_999_200 + FIRST_SEEN_ROUNDING + CLOCK_MARGIN)
        );
        // Recorded at the payment's own time, it is always in time.
        let paid_at = full_payment().block_timestamp;
        for now in [paid_at, paid_at + 1, paid_at + 3_599, paid_at + 86_400] {
            let listing = Listing::new(&envelope(hidden, true, false), &full_payment(), now);
            assert!(listing.latest_payment_time().unwrap() > paid_at);
        }
        let shown = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &full_payment(),
            NOW,
        );
        assert_eq!(shown.latest_payment_time(), None);
        let mut far = listing;
        far.first_seen = Some(first_seen_at(u64::MAX));
        assert_eq!(far.latest_payment_time(), Some(u64::MAX));
    }

    #[test]
    fn key_bytes_order_is_key_order() {
        let keys = [
            ListingKey::MIN,
            key(0, 0, 0, 1),
            key(0, 0, 1, 0),
            key(0, 1, 0, 0),
            key(1, 0, 0, 0),
            key(1, 0, 0, 255),
            key(1, 0, 255, 0),
            key(1, 0, 256, 0),
            key(1, 255, u64::MAX, 255),
            key(1, 256, 0, 0),
            key(256, 0, 0, 0),
            key(1_790_000_000, 70_000_001, 7, 0),
            key(1_790_000_000, 70_000_001, 8, 0),
            key(1_790_000_001, 0, 0, 0),
            key(u64::MAX, u64::MAX, u64::MAX, 255),
        ];
        for (i, a) in keys.iter().enumerate() {
            assert_eq!(ListingKey::from_bytes(&a.to_bytes()), Some(*a));
            for b in &keys[i + 1..] {
                assert!(a < b, "{a:?} < {b:?}");
                assert!(a.to_bytes() < b.to_bytes(), "{a:?} < {b:?} as bytes");
            }
        }
        assert_eq!(ListingKey::MIN, ListingKey::default());
        assert_eq!(ListingKey::MIN.to_bytes(), [0; LISTING_KEY_LEN]);
        assert_eq!(ListingKey::from_bytes(&[0; 55]), None);
        assert_eq!(ListingKey::from_bytes(&[0; 57]), None);

        let bytes = key(0x0102, 0x0304, 0x0506, 0x07).to_bytes();
        assert_eq!(&bytes[..8], &[0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(&bytes[8..16], &[0, 0, 0, 0, 0, 0, 3, 4]);
        assert_eq!(&bytes[16..24], &[0, 0, 0, 0, 0, 0, 5, 6]);
        assert_eq!(bytes[55], 7);
    }

    #[test]
    fn next_is_the_smallest_later_key() {
        let a = key(5, 6, 7, 8);
        assert_eq!(a.next(), key(5, 6, 7, 9));
        assert!(a < a.next());

        let mut full_address = key(5, 6, 7, 0);
        full_address.address = [0xff; 32];
        assert_eq!(full_address.next(), key(5, 6, 8, 0));
        let mut carry = full_address;
        carry.log_index = u64::MAX;
        assert_eq!(carry.next(), key(5, 7, 0, 0));
        carry.block_number = u64::MAX;
        assert_eq!(carry.next(), key(6, 0, 0, 0));

        let mut last = carry;
        last.time = u64::MAX;
        assert_eq!(last.next(), last);
        assert_eq!(last.checked_next(), None);
        assert_eq!(a.checked_next(), Some(a.next()));
        assert_eq!(carry.checked_next(), Some(key(6, 0, 0, 0)));

        // Nothing fits between a key and its next.
        let mut address = [0x11; 32];
        address[31] = 0xfe;
        let k = ListingKey {
            time: 9,
            block_number: 9,
            log_index: 9,
            address,
        };
        let n = k.next();
        assert_eq!(n.address[31], 0xff);
        assert_eq!(n.address[..31], k.address[..31]);
    }

    #[test]
    fn walking_again_goes_back_far_enough() {
        let began = 1_790_003_000;
        let lag = FIRST_SEEN_ROUNDING + CLOCK_MARGIN;
        assert_eq!(
            ListingKey::since(began, 0),
            ListingKey {
                time: began - lag,
                ..ListingKey::MIN
            }
        );
        assert_eq!(ListingKey::since(began, 600).time, began - lag - 600);
        assert_eq!(ListingKey::since(5, 0), ListingKey::MIN);
        assert_eq!(ListingKey::since(began, u64::MAX), ListingKey::MIN);

        // A walk began at 10:50 and ended at a listing paid at 10:50. Then
        // two listings were stored: one hiding its time, paid at 9:30 and
        // stored at 10:55 by a node whose clock says 9:55, so keyed 9:00;
        // and one showing its time, paid at 10:49, its PUT two minutes
        // later.
        let hiding = ShownFields::NONE;
        let hour = first_seen_at(began);
        let at_10_50 = hour + 50 * 60;
        let paid_early = Payment {
            block_timestamp: hour - 30 * 60,
            ..full_payment()
        };
        let hidden = Listing::new(
            &envelope(hiding, true, false),
            &paid_early,
            hour + 55 * 60 - CLOCK_MARGIN,
        );
        assert_eq!(hidden.key().time, hour - 3_600);
        let paid_late = Payment {
            block_timestamp: at_10_50 - 60,
            ..full_payment()
        };
        let shown = Listing::new(
            &envelope(ShownFields::ALL, true, false),
            &paid_late,
            at_10_50 + 60,
        );
        let last_seen = ListingKey {
            time: at_10_50,
            ..ListingKey::MIN
        };
        for listing in [&hidden, &shown] {
            // Behind where the walk stopped...
            assert!(listing.key() < last_seen, "{:?}", listing.key());
            // ...but not behind where the next one starts.
            assert!(listing.key() >= ListingKey::since(at_10_50, 120));
            assert!(listing.key() >= ListingKey::since(at_10_50, 0));
        }
    }

    #[test]
    fn sorted_listings_follow_payment_time() {
        let payment = full_payment();
        let hidden_time = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        let shown_time = Listing::new(&envelope(ShownFields::ALL, true, false), &payment, NOW);
        // First seen in the hour after the payment's block.
        let late = Listing::new(&envelope(hidden_time, true, false), &payment, 1_790_010_000);
        // Recorded by a slow clock: the hour of the payment's block.
        let early = Listing::new(&envelope(hidden_time, true, true), &payment, 1_700_000_000);
        assert_eq!(early.key().time, first_seen_at(payment.block_timestamp));
        let mut listings = [late.clone(), shown_time.clone(), early.clone()];
        listings.sort_by_key(Listing::key);
        assert_eq!(listings, [early, shown_time, late]);
    }
}
