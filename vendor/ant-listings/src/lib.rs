//! Envelopes and listings for storage networks built on Autonomi's
//! `ant-protocol`.
//!
//! A file's data map can be wrapped in an [`Envelope`]: a short, versioned
//! header with flags and optional metadata, in front of the data map or, for
//! a private file, a salted hash of it ([`salted_hash`]). The envelope's
//! address is the file's address. Its [`Flags`] fix, at upload, which of the
//! five payment fields its listing shows ([`ShownFields`]), whether the
//! listing is in the index, and whether the data map is withheld.
//!
//! Nodes recognise envelopes when they store a chunk ([`is_envelope`]), find
//! the full on-chain payment for each one ([`find_payment`]) and record a
//! [`Listing`] with only the shown fields ([`Listing::new`]). Records stored
//! by version 1 read as [`ListingV1`]. Nodes answer the requests in
//! [`message`] on their own topic, [`TOPIC`], so the chunk protocol's message
//! enum is never changed: listings in the index by [`ListingKey`], a page at
//! a time ([`check_list_page`]), and any listing by address.
//!
//! Anyone can check a listing against its envelope and the chain:
//! [`payment_lookup`] says what to fetch, and [`verify_listing_receipts`]
//! gives a [`CheckLevel`]. A listing that shows its quote is
//! [`CheckLevel::Verified`]: its address was paid for by the block the quote
//! was paid in. Paying needs only the address, which the nodes asked to quote
//! learn before the uploader pays, so of several verified listings for one
//! address, the one [`quorum_needed`] of the nodes nearest it serve counts
//! ([`choose_verified`]). One that hides the quote is only
//! [`CheckLevel::Reported`], and counts when [`quorum_needed`] of those nodes
//! serve it ([`merge_copies`]). Either way, the nodes nearest the address
//! set its `first_seen` ([`check_copies`]). The
//! uploader keeps an [`EnvelopeProof`] that proves the payment, hidden fields
//! included, from the chain alone ([`check_proof`]).
//!
//! Payments are read from a [`VaultSet`]: the per-quote vault, and a root
//! vault where the network has one, each by its own address. A root vault
//! records each wave of payments under one key ([`root`]), and its payment
//! counts only where the receipt shows its wave whole, token transfers
//! included. A payment log from any other contract never counts.
//!
//! An indexer reads every node's index with [`IndexWalk`]. A node's pages are
//! only shape-checked, so it can serve as many made-up listings as it likes;
//! the walk reads each node for as long as other nodes back what it sends,
//! and an indexer does per-address work, such as fetching the envelope or
//! reading the chain, only where at least [`QUORUM_THRESHOLD`] of the
//! [`NEAREST_NODES`] nodes nearest the address serve a listing for it. So
//! listings fewer nodes serve cost it nothing, with no ceiling on how many
//! real listings the index holds.
//!
//! A reader can instead follow each node's change feed ([`feed`]): a node
//! numbers every change to what it serves in the index, and answers for an
//! address range with the changes after a given record, as
//! [`DigestEntry`]s, along with the count and [`SetHash`] of what it serves
//! there. [`FeedSync`] keeps a mirror of one node's range, read within the
//! walk's earned allowance, and [`leaves`] splits the address space into the
//! ranges to ask each node about.
//!
//! Nothing here does I/O: callers fetch chunks, receipts and block times
//! themselves and pass them in.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod feed;
pub mod feed_sync;
pub mod flags;
pub mod listing;
pub mod message;
pub mod payment;
pub mod proof;
pub mod root;
pub mod walk;

#[cfg(test)]
mod census;
#[cfg(test)]
mod test_support;
mod wire;

/// The `self_encryption` version envelopes are built with, re-exported so
/// callers build data maps with the same one.
pub use self_encryption;

pub use envelope::{
    encode_data_map, is_envelope, needs_envelope, salted_hash, Envelope, EnvelopeError, Metadata,
    Salt, ENVELOPE_VERSION, ENVELOPE_VERSION_1, MAGIC, MAX_CONTENT_TYPE_LEN, MAX_NAME_LEN,
    SALTED_HASH_LEN, SALT_LEN,
};
pub use feed::{
    leaf_index, leaves, view_hash, AddressRange, DigestEntry, FeedChange, Leaf, SetHash,
};
pub use feed_sync::{FeedOutcome, FeedSync, Pushed};
pub use flags::{Flags, PaymentField, ShownFields};
pub use listing::{
    check_copies, first_seen_at, listing_to_check, median_first_seen, merge_copies, quorum_listing,
    support_among, Listing, ListingError, ListingKey, ListingPayment, ListingV1, MergedListing,
    Payment, PaymentV1, CLOCK_MARGIN, FIRST_SEEN_ROUNDING, LISTING_KEY_LEN,
};
pub use message::{
    check_changes_page, check_get_response, check_list_page, check_push, check_range_page,
    push_request_id, ChangesPage, ChangesRequest, ChangesResponse, FeedError, ListingsBody,
    ListingsMessage, MessageError, PageError, RangeListRequest, RangeListResponse, MAX_LIST_LIMIT,
    MAX_WATCHERS, TOPIC, VIEW_PEERS, WATCH_LEASE,
};
pub use payment::{
    check_offline, choose_verified, find_payment, payment_lookup, quorum_needed, verify_listing,
    verify_listing_receipts, CheckLevel, ChosenVerified, ListingCheck, Lookup, PaidAt,
    PaymentError, PaymentLog, PaymentReceipt, RootVault, VaultSet, DATA_PAYMENT_MADE_TOPIC,
    QUORUM_THRESHOLD,
};
pub use proof::{check_proof, EnvelopeProof, ProofError, ProvenUpload, PROOF_VERSION};
pub use walk::{
    nearest_by_distance, AddressWalk, IndexWalk, NodeReport, WalkOutcome, WalkResult,
    NEAREST_NODES, WALK_EARNING_RANKS, WALK_FREE_LISTINGS, WALK_PER_BACKED, WALK_RETRY_PAGES,
};
