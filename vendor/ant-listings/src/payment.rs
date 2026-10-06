//! Finding and checking a listing's payment on chain.
//!
//! These functions do no I/O. A node finds the full payment for an envelope it
//! is storing with [`find_payment`]. Anyone checking a listing asks
//! [`payment_lookup`] what to fetch, fetches it from its own RPC provider,
//! fetches the envelope at the listing's address from the network, and
//! passes both to [`verify_listing_receipts`] along with the payment vault's
//! address.
//!
//! A paid quote proves that its address was paid for by the block it was
//! paid in, not that this was the upload's payment. Nothing on chain ties a
//! quote's signing key to the nodes that stored the file, and paying a quote
//! takes only the address, not the envelope's bytes. The address is known
//! before the upload is paid: the uploader sends it to each node it asks for
//! a quote, and a gateway that builds the envelope knows it too. So any of
//! them can sign a quote of their own for the address and pay it to
//! themselves before the uploader's payment lands, and anyone who fetches the
//! envelope can do the same later. The earliest payment for an address only
//! dates when the address was first known, not who uploaded the file.
//!
//! What ties a listing to the upload is the nodes nearest its address: each
//! records the payment that came with the upload's PUT, and only that one
//! ([`find_payment`] looks only in the PUT's own transaction). So of several
//! verified listings for one address, keep the one that [`quorum_needed`] of
//! those nodes serve ([`choose_verified`]).

use crate::envelope::Envelope;
use crate::listing::{Listing, ListingError, MergedListing, Payment, CLOCK_MARGIN};
use ant_protocol::evm::PaymentQuote;
use ant_protocol::{verify_quote_content, verify_quote_signature, XorName};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// `keccak256("DataPaymentMade(address,uint256,bytes32)")`: the event the
/// payment vault emits for each paid quote. All three fields are indexed, so
/// they are topics 1 to 3: rewards address, amount and quote hash.
pub const DATA_PAYMENT_MADE_TOPIC: [u8; 32] = [
    0xf9, 0x98, 0x96, 0x0b, 0x1c, 0x6f, 0x0e, 0x0e, 0x89, 0xb7, 0xbb, 0xe6, 0xb6, 0xfb, 0xf3, 0xe0,
    0x3e, 0x6f, 0x08, 0xee, 0xe5, 0xb8, 0x43, 0x08, 0x77, 0xd8, 0xad, 0xb8, 0xe1, 0x49, 0xd5, 0x80,
];

/// The most agreeing nodes a [`CheckLevel::Reported`] listing needs: 4, a
/// majority of the 7 nodes nearest its address. See [`quorum_needed`].
pub const QUORUM_THRESHOLD: usize = 4;

/// How many of `asked` nodes must return the same listing, apart from
/// `first_seen`, for a [`CheckLevel::Reported`] listing to count:
/// `min(QUORUM_THRESHOLD, asked / 2 + 1)`, the chunk protocol's threshold
/// for accepting a chunk without its payment proof. An indexer asking the 7
/// nodes nearest an address needs 4; a node repairing a listing passes the
/// number of close-group peers it asked. Never 0, so no answers never count.
#[must_use]
pub const fn quorum_needed(asked: usize) -> usize {
    let majority = asked / 2 + 1;
    if majority < QUORUM_THRESHOLD {
        majority
    } else {
        QUORUM_THRESHOLD
    }
}

/// One event log from a transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentLog {
    /// The contract that emitted it.
    pub address: [u8; 20],
    /// Its topics, the event signature first.
    pub topics: Vec<[u8; 32]>,
    /// Its position in the block.
    pub log_index: u64,
}

/// The parts of a transaction receipt that a payment check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentReceipt {
    /// The transaction's hash.
    pub tx_hash: [u8; 32],
    /// Whether the transaction succeeded.
    pub success: bool,
    /// The block the transaction is in.
    pub block_number: u64,
    /// The transaction's event logs.
    pub logs: Vec<PaymentLog>,
}

/// Why a payment can't be found or doesn't check out.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaymentError {
    /// The listing's fields don't fit its flags, or it doesn't describe its
    /// envelope ([`ListingError::EnvelopeMismatch`]).
    #[error("malformed listing: {0}")]
    Malformed(#[from] ListingError),
    /// What the listing's shown fields point at is not on chain: the caller
    /// fetched no receipt, or no block timestamp, where one was needed.
    #[error("the payment is not on chain")]
    NotFound,
    /// The receipt is for another transaction.
    #[error("the receipt is for a different transaction")]
    WrongTransaction,
    /// The transaction reverted.
    #[error("the payment transaction failed")]
    Failed,
    /// The receipt's block is not the listing's.
    #[error("the payment is in a different block")]
    WrongBlock,
    /// The block's timestamp is not the listing's.
    #[error("the block time does not match")]
    WrongTimestamp,
    /// The listing's `first_seen` is earlier than any node could have recorded
    /// it: the payment's block is later than
    /// [`Listing::latest_payment_time`].
    #[error("first_seen is before the payment")]
    FirstSeenTooEarly,
    /// The quote can't be decoded or encoded, or is not encoded exactly as
    /// payment proofs encode it with its timestamp in whole seconds.
    #[error("the paid quote cannot be decoded: {0}")]
    BadQuote(String),
    /// The quote is for another address.
    #[error("the paid quote is for a different address")]
    WrongContent,
    /// The quote's ML-DSA-65 signature is invalid.
    #[error("the paid quote's signature is invalid")]
    BadSignature,
    /// The transaction has no vault payment for the quote, or, for a listing
    /// without its quote, none at the shown log index.
    #[error("no payment to the vault for this quote in the transaction")]
    NotPaid,
}

/// Find the full payment for an envelope chunk, as a node does when it stores
/// one.
///
/// `quotes` are the quotes in the chunk's payment proof. Exactly one of them,
/// the one the uploader paid, has a `DataPaymentMade` event in the receipt.
/// The node then records [`Listing::new`], which keeps only the fields the
/// envelope shows. The payment's quote is encoded with its timestamp in whole
/// seconds (see [`ListingPayment::quote`](crate::ListingPayment::quote)).
///
/// # Errors
///
/// Returns an error if the transaction failed, no quote for `address` was
/// paid to `vault` in it, or the paid quote's signature is invalid.
pub fn find_payment(
    address: &XorName,
    quotes: &[PaymentQuote],
    receipt: &PaymentReceipt,
    block_timestamp: u64,
    vault: &[u8; 20],
) -> Result<Payment, PaymentError> {
    if !receipt.success {
        return Err(PaymentError::Failed);
    }
    let (quote, log) = quotes
        .iter()
        .filter(|quote| verify_quote_content(quote, address))
        .find_map(|quote| {
            receipt
                .logs
                .iter()
                .find(|log| pays(log, vault, quote))
                .map(|log| (quote, log))
        })
        .ok_or(PaymentError::NotPaid)?;
    if !verify_quote_signature(quote) {
        return Err(PaymentError::BadSignature);
    }
    Ok(Payment {
        tx_hash: receipt.tx_hash,
        block_number: receipt.block_number,
        block_timestamp,
        log_index: log.log_index,
        quote: encode_quote(quote)?,
    })
}

/// What to fetch from the chain to check a listing, from [`payment_lookup`].
///
/// Fetch the receipt as described, and the timestamp of its block if the
/// listing shows the block timestamp or has `first_seen`: [`verify_listing`]
/// needs it then, and ignores it otherwise, so fetching it whenever there is
/// a receipt is simplest. For [`Lookup::Block`], always fetch the timestamp
/// of `block_number`: it shows that the block exists. Pass `None` for
/// anything the chain doesn't have. Then call [`verify_listing_receipts`]
/// with everything found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// The tx hash is shown: fetch the receipt of `tx_hash`
    /// (`eth_getTransactionReceipt`).
    Transaction {
        /// The listing's tx hash.
        tx_hash: [u8; 32],
    },
    /// The quote is shown but the tx hash is hidden: find the vault's
    /// `DataPaymentMade` logs whose topic 3 is `quote_hash` (`eth_getLogs` on
    /// the vault, topics `[DATA_PAYMENT_MADE_TOPIC, *, *, quote_hash]`), then
    /// fetch the receipt of the transaction that emitted each.
    ///
    /// Search `block_number` alone if given. Otherwise search backwards from
    /// the block at `not_after` (or the latest block) to the block at
    /// `search_from`, and, if that finds nothing, on back to the vault's
    /// first block: `search_from` is only a hint.
    ///
    /// A vault can emit more than one such log if the quote is paid again,
    /// as upstream's `PaymentVaultV2` allows. Pass every receipt found to
    /// [`verify_listing_receipts`].
    Quote {
        /// The paid quote's hash, as the vault event carries it.
        quote_hash: [u8; 32],
        /// The listing's block number, if shown: search that block only.
        block_number: Option<u64>,
        /// Where to start searching, in Unix seconds: the quote's own
        /// timestamp less [`CLOCK_MARGIN`], and no
        /// later than `not_after`. The quote's timestamp is whatever the node
        /// that signed it put there, so this is untrusted: anyone's own quote
        /// can carry the Unix epoch (giving 0) or a time years ahead. The
        /// payment came after the quote, but nodes accept quotes whatever
        /// their timestamp, so this is only where to start.
        search_from: u64,
        /// The latest block timestamp, in Unix seconds, the payment can have,
        /// when the listing has `first_seen`
        /// ([`Listing::latest_payment_time`]): later blocks need not be
        /// searched, since a payment in one fails [`verify_listing`]. `None`
        /// otherwise.
        not_after: Option<u64>,
    },
    /// The block number and log index are shown, but neither the tx hash nor
    /// the quote: find the vault's `DataPaymentMade` log at `log_index` in
    /// block `block_number` (`eth_getLogs` on the vault for that block), then
    /// fetch the receipt of the transaction that emitted it.
    BlockLog {
        /// The listing's block number.
        block_number: u64,
        /// The listing's log index.
        log_index: u64,
    },
    /// Only the block number is shown, of the fields that locate a payment:
    /// fetch the block's timestamp (`eth_getBlockByNumber`), and no receipt.
    Block {
        /// The listing's block number.
        block_number: u64,
    },
    /// Nothing that locates a payment is shown: fetch nothing.
    Nothing,
}

/// How far a listing checks out, from [`verify_listing`]. At either level the
/// listing describes the envelope at its address, so its flags, metadata and
/// size are the ones the uploader stored; the metadata is still only what the
/// uploader declared. `first_seen` is only checked not to be in the future,
/// and not to be before the payment where the payment's block is known: take
/// it from the nodes nearest the address
/// ([`MergedListing::checked_listing_among`]), at either level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckLevel {
    /// The quote is shown: it names the file's address, is signed, and was
    /// paid on chain, and every shown payment field matches the chain.
    ///
    /// That proves the address was paid for by the block the quote was paid
    /// in ([`ListingCheck::paid_at`]), not that this was the upload's
    /// payment: a node asked to quote for the upload learns the address
    /// before the uploader pays, and anyone who fetches the envelope learns
    /// it later, and either can sign a quote of their own for it and pay it
    /// to themselves, earlier or later. Of several verified listings for one
    /// address, keep the one the nodes nearest it agree on
    /// ([`choose_verified`]).
    Verified,
    /// The quote is hidden. Every shown payment field that can be checked
    /// matches the chain, but nothing ties the payment to this file: the
    /// listing rests on the nodes that recorded it at upload. Count how many
    /// of the nodes nearest the address serve it
    /// ([`MergedListing::count_among`](crate::MergedListing::count_among)),
    /// and trust it only from [`quorum_needed`] of them.
    Reported,
}

/// Where on chain a quote's payment is: the block, and the position in it of
/// the vault's `DataPaymentMade` log. Ordered by block, then log index, so
/// the smaller is the earlier payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PaidAt {
    /// The block the payment is in.
    pub block_number: u64,
    /// The position of the payment's log in the block.
    pub log_index: u64,
}

/// What [`verify_listing`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListingCheck {
    /// How far the listing checks out.
    pub level: CheckLevel,
    /// For a [`CheckLevel::Verified`] listing, where its quote was paid: the
    /// receipt's block and the log paying the quote, also when the listing
    /// hides them. `None` for a [`CheckLevel::Reported`] one, whose payment
    /// isn't tied to the file. For choosing among several verified listings
    /// for one address ([`choose_verified`]).
    pub paid_at: Option<PaidAt>,
}

/// The verified listing [`choose_verified`] kept for an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChosenVerified<T> {
    /// What the caller passed with the chosen group, such as the listing it
    /// checked.
    pub item: T,
    /// Where its quote was paid.
    pub paid_at: PaidAt,
    /// How many of the nearest nodes served it
    /// ([`MergedListing::count_among`]).
    pub count: usize,
    /// Whether `count` reached [`quorum_needed`] of the nearest nodes: the
    /// payment the close group recorded from the upload's PUT. When false, no
    /// verified copy had a quorum and the earliest payment was kept instead,
    /// which a node asked to quote for the upload could have made before
    /// the uploader's: show it as such, or ask again later.
    pub quorum: bool,
}

/// Of the verified listings for one address, the one to keep: the one that
/// [`quorum_needed`] of `nearest` serve.
///
/// Each of `checked` is a group of copies for the address, what the caller
/// wants back with it (such as the listing
/// [`MergedListing::checked_listing_among`] gave), and that listing's check.
/// [`CheckLevel::Reported`] ones are ignored. `nearest` is the nodes nearest
/// the address for an indexer, or the close-group peers asked for a node
/// repairing a listing.
///
/// A verified listing proves only that its address was paid for by its
/// block, and paying needs only the address, which the nodes asked to quote
/// learn before the uploader pays. So the earliest payment is not
/// necessarily the upload's: one quoting node can sign a quote of its own,
/// pay it first, and serve the listing built from it. What the upload's
/// payment has is the close group: each of its nodes recorded the payment
/// that came with the PUT. So:
///
/// 1. Of the groups that `quorum_needed(nearest.len())` of `nearest` serve,
///    keep the one paid first, with `quorum` set. Each node counts once per
///    address, so two groups can both have a quorum only when `nearest` has
///    more than 7 nodes.
/// 2. If none has a quorum, keep the one paid first, with `quorum` unset: a
///    fallback that a quoting node could have front-run.
///
/// On a tie, the first. `None` if none is verified.
pub fn choose_verified<'g, P: PartialEq + 'g, T>(
    checked: impl IntoIterator<Item = (&'g MergedListing<P>, T, ListingCheck)>,
    nearest: &[P],
) -> Option<ChosenVerified<T>> {
    let needed = quorum_needed(nearest.len());
    let mut with_quorum = Vec::new();
    let mut without = Vec::new();
    for (group, item, check) in checked {
        let count = group.count_among(nearest);
        let quorum = count >= needed;
        let candidate = ((item, count, quorum), check);
        if quorum {
            with_quorum.push(candidate);
        } else {
            without.push(candidate);
        }
    }
    let ((item, count, quorum), paid_at) =
        earliest_verified(with_quorum).or_else(|| earliest_verified(without))?;
    Some(ChosenVerified {
        item,
        paid_at,
        count,
        quorum,
    })
}

/// Of checked items, the [`CheckLevel::Verified`] one with the smallest
/// [`ListingCheck::paid_at`], with where it was paid. `None` if none is
/// verified. On a tie, the first.
fn earliest_verified<T>(
    checked: impl IntoIterator<Item = (T, ListingCheck)>,
) -> Option<(T, PaidAt)> {
    let mut earliest: Option<(T, PaidAt)> = None;
    for (item, check) in checked {
        let Some(paid_at) = check
            .paid_at
            .filter(|_| check.level == CheckLevel::Verified)
        else {
            continue;
        };
        if earliest.as_ref().is_none_or(|(_, first)| paid_at < *first) {
            earliest = Some((item, paid_at));
        }
    }
    earliest
}

/// What to fetch to check `listing`: by tx hash if shown; else by the quote's
/// hash if the quote is shown; else by block number and log index; else the
/// block alone; else nothing.
///
/// # Errors
///
/// Returns [`PaymentError::Malformed`] if the listing's fields don't fit its
/// flags, or [`PaymentError::BadQuote`] if its quote can't be decoded.
pub fn payment_lookup(listing: &Listing) -> Result<Lookup, PaymentError> {
    listing.validate()?;
    let payment = &listing.payment;
    if let Some(tx_hash) = payment.tx_hash {
        return Ok(Lookup::Transaction { tx_hash });
    }
    if let Some(quote) = &payment.quote {
        let quote = decode_quote(quote)?;
        let quoted_at = quote
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let not_after = listing.latest_payment_time();
        let search_from = quoted_at.saturating_sub(CLOCK_MARGIN);
        return Ok(Lookup::Quote {
            quote_hash: quote.hash().0,
            block_number: payment.block_number,
            search_from: not_after.map_or(search_from, |latest| search_from.min(latest)),
            not_after,
        });
    }
    Ok(match (payment.block_number, payment.log_index) {
        (Some(block_number), Some(log_index)) => Lookup::BlockLog {
            block_number,
            log_index,
        },
        (Some(block_number), None) => Lookup::Block { block_number },
        (None, _) => Lookup::Nothing,
    })
}

/// Every check of `listing` against `envelope` that needs nothing from the
/// chain, to make before looking a copy up: it fits its flags, describes the
/// envelope, and a shown quote decodes, names the address and is signed. A
/// copy that fails can't check out whatever the chain says, so it is never
/// looked up. Its time is not checked here: each node's date is checked on
/// its own once the chain has answered, and a few nodes dating it in the
/// future must not stop the lookup.
///
/// # Errors
///
/// Returns the first check that fails, as [`verify_listing`] would.
pub fn check_offline(
    listing: &Listing,
    envelope: &Envelope,
    vault: &[u8; 20],
) -> Result<(), PaymentError> {
    match verify_listing(listing, envelope, None, None, vault, u64::MAX) {
        // Nothing to look up, or something to look up that was not given.
        Ok(_) | Err(PaymentError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Check a listing against the envelope at its address and against one
/// receipt, as an indexer, a node receiving a listing from another node, or
/// anyone else can. [`verify_listing_receipts`] checks it against everything
/// a lookup found, and is what callers want.
///
/// `envelope` is the envelope fetched from the network at the listing's
/// address. `receipt` and `block_timestamp` are what the caller fetched for
/// [`payment_lookup`], `None` where the chain had nothing. `now` is the
/// caller's clock, in Unix seconds.
///
/// First the listing must fit its flags ([`Listing::validate`]), have no time
/// in the future ([`Listing::check_not_in_future`]) and describe `envelope`
/// ([`Listing::matches`]): the same address, flags, metadata and size.
/// Then:
///
/// - Quote shown: the quote names the address and is signed, the receipt is
///   the shown tx (if shown), succeeded, is in the shown block (if shown), at
///   the shown time (if shown), and pays the quote to `vault` at the shown log
///   index (or anywhere, if hidden): [`CheckLevel::Verified`], with where the
///   quote was paid.
/// - Quote hidden: each shown field is checked against what was fetched: the
///   tx, its success, the block, the time, and a vault `DataPaymentMade` log
///   with a non-zero amount at the shown log index (or anywhere in the tx):
///   [`CheckLevel::Reported`].
/// - Quote, tx hash and block number all hidden: nothing can be fetched, so
///   a shown timestamp or log index is not checked: [`CheckLevel::Reported`].
///
/// Wherever the payment's block is known and the listing has `first_seen`,
/// the block's timestamp is needed and must be no later than
/// [`Listing::latest_payment_time`]: no node records a listing before it is
/// paid.
///
/// # Errors
///
/// Returns the first check that fails: [`PaymentError::Malformed`] if the
/// listing doesn't fit its flags or its envelope or its time is in the
/// future, and otherwise for any shown field that disagrees with the chain.
pub fn verify_listing(
    listing: &Listing,
    envelope: &Envelope,
    receipt: Option<&PaymentReceipt>,
    block_timestamp: Option<u64>,
    vault: &[u8; 20],
    now: u64,
) -> Result<ListingCheck, PaymentError> {
    let lookup = payment_lookup(listing)?;
    listing.check_not_in_future(now)?;
    if !listing.matches(envelope) {
        return Err(ListingError::EnvelopeMismatch.into());
    }
    let payment = &listing.payment;
    if let Some(quote) = &payment.quote {
        let quote = decode_quote(quote)?;
        check_quote(&quote, &listing.address)?;
        let receipt = receipt.ok_or(PaymentError::NotFound)?;
        check_receipt(listing, receipt, block_timestamp)?;
        let log = receipt
            .logs
            .iter()
            .filter(|log| at_index(log, payment.log_index) && pays(log, vault, &quote))
            .min_by_key(|log| log.log_index)
            .ok_or(PaymentError::NotPaid)?;
        return Ok(ListingCheck {
            level: CheckLevel::Verified,
            paid_at: Some(PaidAt {
                block_number: receipt.block_number,
                log_index: log.log_index,
            }),
        });
    }
    match lookup {
        Lookup::Transaction { .. } | Lookup::BlockLog { .. } => {
            let receipt = receipt.ok_or(PaymentError::NotFound)?;
            check_receipt(listing, receipt, block_timestamp)?;
            let paid = receipt
                .logs
                .iter()
                .any(|log| at_index(log, payment.log_index) && is_vault_payment(log, vault));
            if !paid {
                return Err(PaymentError::NotPaid);
            }
        }
        Lookup::Block { .. } => {
            let timestamp = block_timestamp.ok_or(PaymentError::NotFound)?;
            check_block_time(listing, Some(timestamp))?;
        }
        Lookup::Quote { .. } | Lookup::Nothing => {}
    }
    Ok(ListingCheck {
        level: CheckLevel::Reported,
        paid_at: None,
    })
}

/// Check a listing against the envelope at its address and against
/// everything the caller fetched for [`payment_lookup`]: [`verify_listing`]
/// with each receipt, and one answer.
///
/// `fetched` holds each receipt found with its block's timestamp, or for
/// [`Lookup::Block`] no receipt and the block's timestamp: `None` wherever
/// the chain had nothing. Empty means the search found nothing, which is
/// checked as one `(None, None)`: [`Lookup::Nothing`] needs nothing, so its
/// listing is still [`CheckLevel::Reported`], and anything else is
/// [`PaymentError::NotFound`]. `now` is the caller's clock, in Unix seconds.
///
/// Several receipts come from a [`Lookup::Quote`] when the quote was paid
/// more than once, which the vault allows. The answer is then:
///
/// 1. the [`CheckLevel::Verified`] result with the earliest
///    [`ListingCheck::paid_at`], whatever order the receipts came in, so a
///    later payment of the same quote by anyone never moves it;
/// 2. else the first result that checks out;
/// 3. else the first error that isn't [`PaymentError::NotFound`], since
///    something was found and it disagrees;
/// 4. else [`PaymentError::NotFound`].
///
/// The earliest payment of a quote is the first time it was paid, by
/// whoever paid it: the node that signed the quote can pay it before the
/// uploader does.
///
/// # Errors
///
/// As above, from [`verify_listing`].
pub fn verify_listing_receipts(
    listing: &Listing,
    envelope: &Envelope,
    fetched: &[(Option<PaymentReceipt>, Option<u64>)],
    vault: &[u8; 20],
    now: u64,
) -> Result<ListingCheck, PaymentError> {
    let nothing = [(None, None)];
    let fetched = if fetched.is_empty() {
        &nothing[..]
    } else {
        fetched
    };
    let mut passed = Vec::new();
    let mut error = None;
    for (receipt, timestamp) in fetched {
        match verify_listing(listing, envelope, receipt.as_ref(), *timestamp, vault, now) {
            Ok(check) => passed.push(check),
            Err(PaymentError::NotFound) => {}
            Err(other) => {
                error.get_or_insert(other);
            }
        }
    }
    if let Some((check, _)) = earliest_verified(passed.iter().map(|check| (*check, *check))) {
        return Ok(check);
    }
    match (passed.first(), error) {
        (Some(check), _) => Ok(*check),
        (None, Some(error)) => Err(error),
        (None, None) => Err(PaymentError::NotFound),
    }
}

/// The receipt's own fields against the listing's shown ones.
fn check_receipt(
    listing: &Listing,
    receipt: &PaymentReceipt,
    block_timestamp: Option<u64>,
) -> Result<(), PaymentError> {
    let payment = &listing.payment;
    if payment
        .tx_hash
        .is_some_and(|tx_hash| tx_hash != receipt.tx_hash)
    {
        return Err(PaymentError::WrongTransaction);
    }
    if !receipt.success {
        return Err(PaymentError::Failed);
    }
    if payment
        .block_number
        .is_some_and(|block| block != receipt.block_number)
    {
        return Err(PaymentError::WrongBlock);
    }
    check_block_time(listing, block_timestamp)
}

/// The payment block's timestamp against the shown one, and against
/// `first_seen`. Needed only if the listing has either.
fn check_block_time(listing: &Listing, block_timestamp: Option<u64>) -> Result<(), PaymentError> {
    let shown = listing.payment.block_timestamp;
    let latest = listing.latest_payment_time();
    if shown.is_none() && latest.is_none() {
        return Ok(());
    }
    let timestamp = block_timestamp.ok_or(PaymentError::NotFound)?;
    if shown.is_some_and(|shown| shown != timestamp) {
        return Err(PaymentError::WrongTimestamp);
    }
    if latest.is_some_and(|latest| timestamp > latest) {
        return Err(PaymentError::FirstSeenTooEarly);
    }
    Ok(())
}

/// Decode a paid quote, accepting only the bytes [`encode_quote`] gives for
/// it: no trailing bytes, no other msgpack encoding and no fraction of a
/// second in the timestamp, so copies of a listing that carry the same quote
/// carry the same bytes.
pub(crate) fn decode_quote(bytes: &[u8]) -> Result<PaymentQuote, PaymentError> {
    let quote = rmp_serde::from_slice(bytes).map_err(|e| PaymentError::BadQuote(e.to_string()))?;
    if encode_quote(&quote)? != bytes {
        return Err(PaymentError::BadQuote("not canonical".into()));
    }
    Ok(quote)
}

/// A quote's bytes as listings and proofs carry them: msgpack, as payment
/// proofs encode it, with the timestamp truncated to whole seconds. A quote's
/// signature and hash cover only whole seconds, so the fraction a node's
/// clock adds could be changed without either noticing, giving one paid
/// quote a billion encodings. Truncated, each quote has one, and nothing
/// that can be checked is lost.
pub(crate) fn encode_quote(quote: &PaymentQuote) -> Result<Vec<u8>, PaymentError> {
    let mut quote = quote.clone();
    quote.timestamp = whole_seconds(quote.timestamp);
    rmp_serde::to_vec(&quote).map_err(|e| PaymentError::BadQuote(e.to_string()))
}

/// `time` without its fraction of a second. A time before the Unix epoch
/// becomes the epoch, as a quote's signature reads it.
fn whole_seconds(time: SystemTime) -> SystemTime {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// Quote bytes from a version 1 record, re-encoded as [`encode_quote`]
/// encodes them, or kept as they are if they don't decode (such a listing
/// fails its check as before).
pub(crate) fn canonical_quote(bytes: Vec<u8>) -> Vec<u8> {
    rmp_serde::from_slice::<PaymentQuote>(&bytes)
        .ok()
        .and_then(|quote| encode_quote(&quote).ok())
        .unwrap_or(bytes)
}

/// The quote names `address` and is signed by the key it carries.
pub(crate) fn check_quote(quote: &PaymentQuote, address: &XorName) -> Result<(), PaymentError> {
    if !verify_quote_content(quote, address) {
        return Err(PaymentError::WrongContent);
    }
    if !verify_quote_signature(quote) {
        return Err(PaymentError::BadSignature);
    }
    Ok(())
}

fn at_index(log: &PaymentLog, log_index: Option<u64>) -> bool {
    log_index.is_none_or(|index| log.log_index == index)
}

/// Whether `log` is a vault `DataPaymentMade` event with a non-zero amount.
fn is_vault_payment(log: &PaymentLog, vault: &[u8; 20]) -> bool {
    log.address == *vault
        && log.topics.len() == 4
        && log.topics[0] == DATA_PAYMENT_MADE_TOPIC
        && log.topics[2] != [0u8; 32]
}

/// Whether `log` is the vault's payment, of a non-zero amount, for `quote`.
pub(crate) fn pays(log: &PaymentLog, vault: &[u8; 20], quote: &PaymentQuote) -> bool {
    let mut rewards_topic = [0u8; 32];
    rewards_topic[12..].copy_from_slice(quote.rewards_address.as_slice());
    is_vault_payment(log, vault)
        && log.topics[1] == rewards_topic
        && log.topics[3] == quote.hash().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Metadata, Salt};
    use crate::flags::{Flags, PaymentField, ShownFields};
    use crate::listing::{first_seen_at, merge_copies, FIRST_SEEN_ROUNDING};
    use crate::listing::{ListingV1, PaymentV1};
    use crate::proof::{check_proof, EnvelopeProof};
    use crate::test_support::{
        data_map, metadata, payment_log, receipt, self_issued_quote, signed_quote, signed_quote_at,
        with_nanos, BLOCK_TIME, VAULT,
    };
    use ant_protocol::evm::Amount;
    use sha3::{Digest, Keccak256};

    const TX: [u8; 32] = [0x77; 32];
    const BLOCK: u64 = 1_000;
    const LOG_INDEX: u64 = 4;
    const HEAD: u64 = 2_000;
    const NOW: u64 = BLOCK_TIME + 30;

    /// Block timestamps: two seconds a block, up to the head.
    fn block_time(block: u64) -> Option<u64> {
        (block <= HEAD).then(|| BLOCK_TIME - 2 * BLOCK + 2 * block)
    }

    /// What a caller fetched for a [`Lookup`]: a receipt, and the timestamp
    /// of its block.
    type Fetched = (Option<PaymentReceipt>, Option<u64>);

    /// The salt withheld test envelopes are hashed with.
    const SALT: Salt = [0x5a; 32];

    /// Every valid flags byte: 32 shown sets, in the index or not, readable
    /// or withheld.
    fn every_flags() -> impl Iterator<Item = Flags> {
        (0..Flags::RESERVED).map(|byte| Flags::from_byte(byte).unwrap())
    }

    /// The flags whose listings have `first_seen`: in the index, hiding the
    /// block timestamp, readable or withheld.
    fn dated_by_first_seen() -> impl Iterator<Item = Flags> {
        every_flags()
            .filter(|flags| flags.in_index && !flags.shown.contains(PaymentField::BlockTimestamp))
    }

    /// [`verify_listing`] at [`NOW`], giving only the level.
    fn verify_now(
        listing: &Listing,
        envelope: &Envelope,
        receipt: Option<&PaymentReceipt>,
        block_timestamp: Option<u64>,
        vault: &[u8; 20],
    ) -> Result<CheckLevel, PaymentError> {
        verify_listing(listing, envelope, receipt, block_timestamp, vault, NOW)
            .map(|check| check.level)
    }

    /// A chain holding some receipts, which fetches what a [`Lookup`] says, as
    /// a caller of [`verify_listing`] does.
    struct Chain {
        receipts: Vec<PaymentReceipt>,
    }

    impl Chain {
        /// What `lookup` finds: one receipt, or one for each payment of a quote
        /// paid more than once, each with its block's timestamp; for a block
        /// alone, its timestamp; nothing when nothing is found.
        fn fetch(&self, lookup: Lookup) -> Vec<Fetched> {
            let vault_log = |log: &PaymentLog| {
                log.address == VAULT
                    && log.topics.len() == 4
                    && log.topics[0] == DATA_PAYMENT_MADE_TOPIC
            };
            let found: Vec<&PaymentReceipt> = match lookup {
                Lookup::Transaction { tx_hash } => self
                    .receipts
                    .iter()
                    .filter(|r| r.tx_hash == tx_hash)
                    .collect(),
                Lookup::Quote {
                    quote_hash,
                    block_number,
                    not_after,
                    ..
                } => self
                    .receipts
                    .iter()
                    .filter(|r| {
                        block_number.is_none_or(|block| r.block_number == block)
                            && not_after.is_none_or(|latest| {
                                block_time(r.block_number).is_some_and(|time| time <= latest)
                            })
                            && r.logs
                                .iter()
                                .any(|log| vault_log(log) && log.topics[3] == quote_hash)
                    })
                    .collect(),
                Lookup::BlockLog {
                    block_number,
                    log_index,
                } => self
                    .receipts
                    .iter()
                    .filter(|r| {
                        r.block_number == block_number
                            && r.logs
                                .iter()
                                .any(|log| vault_log(log) && log.log_index == log_index)
                    })
                    .collect(),
                Lookup::Block { block_number } => return vec![(None, block_time(block_number))],
                Lookup::Nothing => return Vec::new(),
            };
            found
                .into_iter()
                .map(|r| (Some(r.clone()), block_time(r.block_number)))
                .collect()
        }

        /// Check `listing` at `now` as a caller does: fetch what it says,
        /// and check it against everything found.
        fn check(
            &self,
            listing: &Listing,
            envelope: &Envelope,
            now: u64,
        ) -> Result<ListingCheck, PaymentError> {
            let fetched = self.fetch(payment_lookup(listing)?);
            verify_listing_receipts(listing, envelope, &fetched, &VAULT, now)
        }

        /// [`check`](Self::check) at [`NOW`], giving only the level.
        fn verify(
            &self,
            listing: &Listing,
            envelope: &Envelope,
        ) -> Result<CheckLevel, PaymentError> {
            self.check(listing, envelope, NOW).map(|check| check.level)
        }
    }

    struct Fixture {
        envelope: Envelope,
        payment: Payment,
        unpaid_quote: Vec<u8>,
        chain: Chain,
    }

    impl Fixture {
        /// The listing a node records for the envelope.
        fn listing(&self) -> Listing {
            Listing::new(&self.envelope, &self.payment, NOW)
        }

        /// Check a listing against the envelope and the chain.
        fn verify(&self, listing: &Listing) -> Result<CheckLevel, PaymentError> {
            self.chain.verify(listing, &self.envelope)
        }

        /// Check a group of copies as a caller does: fetch once, for the
        /// listing as the nearest nodes' median gives it, then check the
        /// listing, with each nearest node's `first_seen`, against that.
        fn check_group(
            &self,
            group: &crate::MergedListing<u8>,
            nearest: &[u8],
        ) -> Result<(Listing, ListingCheck), PaymentError> {
            let fetched = match group.listing_among(nearest) {
                Some(listing) => self.chain.fetch(payment_lookup(&listing)?),
                None => Vec::new(),
            };
            group.checked_listing_among(nearest, |listing| {
                verify_listing_receipts(listing, &self.envelope, &fetched, &VAULT, NOW)
            })
        }
    }

    /// A readable envelope with these flags, paid at log index 4 of a
    /// transaction that also pays another chunk at index 3, and a later
    /// transaction paying something else.
    fn fixture(shown: ShownFields, in_index: bool) -> Fixture {
        fixture_flags(Flags {
            shown,
            in_index,
            withheld: false,
        })
    }

    /// [`fixture`] for any flags: a withheld envelope is hashed with
    /// [`SALT`].
    fn fixture_flags(flags: Flags) -> Fixture {
        let map = data_map(&[10, 10, 10]);
        let meta = metadata(Some("text/plain"), Some("a.txt"));
        let envelope = if flags.withheld {
            Envelope::withheld(&map, &SALT, meta, flags.shown, flags.in_index)
        } else {
            Envelope::readable(&map, meta, flags.shown, flags.in_index)
        }
        .unwrap();
        assert_eq!(envelope.flags(), flags);
        fixture_for(envelope)
    }

    /// A version 1 envelope, as the first release wrote it, named with a
    /// name only version 1's rule allows, paid as [`fixture`]'s.
    fn fixture_v1(name: &str) -> Fixture {
        let mut bytes = b"\0ANTLIST\x01\x0atext/plain".to_vec();
        bytes.push(u8::try_from(name.len()).unwrap());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&rmp_serde::to_vec(&data_map(&[10, 10, 10])).unwrap());
        let envelope = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(envelope.version(), crate::ENVELOPE_VERSION_1);
        assert_eq!(envelope.to_bytes(), bytes);
        fixture_for(envelope)
    }

    /// [`fixture`] for any envelope.
    fn fixture_for(envelope: Envelope) -> Fixture {
        let address = envelope.address();
        let paid = signed_quote(address);
        let other = signed_quote([9; 32]);
        let unpaid = signed_quote(address);
        let chain = Chain {
            receipts: vec![
                receipt(
                    TX,
                    BLOCK,
                    vec![payment_log(&other, 3), payment_log(&paid, LOG_INDEX)],
                ),
                receipt([0x88; 32], BLOCK + 1, vec![payment_log(&other, 0)]),
            ],
        };
        let payment = find_payment(
            &address,
            &[other, unpaid.clone(), paid],
            &chain.receipts[0],
            block_time(BLOCK).unwrap(),
            &VAULT,
        )
        .unwrap();
        Fixture {
            envelope,
            payment,
            unpaid_quote: encode_quote(&unpaid).unwrap(),
            chain,
        }
    }

    /// [`fixture`] in the index, showing `shown`.
    fn fixture_with(shown: &[PaymentField]) -> Fixture {
        fixture(shown.iter().copied().collect(), true)
    }

    /// Change one shown field of `listing` to a value the chain disagrees
    /// with.
    fn tamper(listing: &mut Listing, field: PaymentField, unpaid_quote: &[u8]) {
        let payment = &mut listing.payment;
        match field {
            PaymentField::TxHash => payment.tx_hash = Some([0xee; 32]),
            PaymentField::BlockNumber => payment.block_number = Some(BLOCK + 1),
            PaymentField::BlockTimestamp => {
                payment.block_timestamp = payment.block_timestamp.map(|t| t + 1);
            }
            PaymentField::LogIndex => payment.log_index = Some(LOG_INDEX + 1),
            PaymentField::Quote => payment.quote = Some(unpaid_quote.to_vec()),
        }
    }

    /// Whether changing `field` can be caught when `shown` is shown: always if
    /// the tx hash or quote locates the payment, or the block and log index
    /// do; with the block alone, only through a shown timestamp; never when
    /// nothing locates it.
    fn detectable(shown: ShownFields, field: PaymentField) -> bool {
        use PaymentField::*;
        if shown.contains(Quote) || shown.contains(TxHash) {
            return true;
        }
        if !shown.contains(BlockNumber) {
            return false;
        }
        shown.contains(LogIndex)
            || field == BlockTimestamp
            || (field == BlockNumber && shown.contains(BlockTimestamp))
    }

    #[test]
    fn topic_is_the_event_signature_hash() {
        let hash = Keccak256::digest(b"DataPaymentMade(address,uint256,bytes32)");
        assert_eq!(hash.as_slice(), DATA_PAYMENT_MADE_TOPIC.as_slice());
    }

    #[test]
    fn finds_the_full_payment() {
        let fixture = fixture(ShownFields::ALL, true);
        let payment = &fixture.payment;
        assert_eq!(payment.tx_hash, TX);
        assert_eq!(payment.block_number, BLOCK);
        assert_eq!(payment.block_timestamp, block_time(BLOCK).unwrap());
        assert_eq!(payment.log_index, LOG_INDEX);
        let quote = decode_quote(&payment.quote).unwrap();
        assert!(verify_quote_content(&quote, &fixture.envelope.address()));
    }

    #[test]
    fn finds_nothing_when_the_quote_was_not_paid() {
        let fixture = fixture(ShownFields::ALL, true);
        let address = fixture.envelope.address();
        let unpaid = decode_quote(&fixture.unpaid_quote).unwrap();
        let receipt = &fixture.chain.receipts[0];
        assert_eq!(
            find_payment(&address, &[unpaid], receipt, BLOCK_TIME, &VAULT),
            Err(PaymentError::NotPaid)
        );
        let mut failed = receipt.clone();
        failed.success = false;
        let paid = decode_quote(&fixture.payment.quote).unwrap();
        assert_eq!(
            find_payment(&address, &[paid], &failed, BLOCK_TIME, &VAULT),
            Err(PaymentError::Failed)
        );
    }

    #[test]
    fn lookups_follow_the_shown_fields() {
        let paid_at = block_time(BLOCK).unwrap();
        for flags in every_flags() {
            let shown = flags.shown;
            let fixture = fixture_flags(flags);
            let listing = fixture.listing();
            let quote_hash = decode_quote(&fixture.payment.quote).unwrap().hash().0;
            let has = |field| shown.contains(field);
            let first_seen = (flags.in_index && !has(PaymentField::BlockTimestamp))
                .then_some(first_seen_at(NOW));
            assert_eq!(listing.first_seen, first_seen);
            let expected = if has(PaymentField::TxHash) {
                Lookup::Transaction { tx_hash: TX }
            } else if has(PaymentField::Quote) {
                // The quote's own timestamp, less the margin.
                let search_from = BLOCK_TIME - 60 - CLOCK_MARGIN;
                let not_after =
                    first_seen.map(|first_seen| first_seen + FIRST_SEEN_ROUNDING + CLOCK_MARGIN);
                // The payment is in the window to search.
                assert!(search_from <= paid_at);
                assert!(not_after.is_none_or(|not_after| paid_at <= not_after));
                Lookup::Quote {
                    quote_hash,
                    block_number: has(PaymentField::BlockNumber).then_some(BLOCK),
                    search_from,
                    not_after,
                }
            } else if has(PaymentField::BlockNumber) && has(PaymentField::LogIndex) {
                Lookup::BlockLog {
                    block_number: BLOCK,
                    log_index: LOG_INDEX,
                }
            } else if has(PaymentField::BlockNumber) {
                Lookup::Block {
                    block_number: BLOCK,
                }
            } else {
                Lookup::Nothing
            };
            assert_eq!(payment_lookup(&listing), Ok(expected), "{flags:?}");
        }
    }

    #[test]
    fn the_quote_search_window_never_underflows_or_inverts() {
        // Anyone's own quote can carry any timestamp: the Unix epoch, a
        // moment before it, or years ahead.
        let shown = ShownFields::NONE.with(PaymentField::Quote);
        for (timestamp, in_index, expected) in [
            (UNIX_EPOCH, true, 0),
            (UNIX_EPOCH, false, 0),
            (UNIX_EPOCH - Duration::from_secs(5), true, 0),
            (UNIX_EPOCH + Duration::from_secs(CLOCK_MARGIN - 1), false, 0),
            (
                UNIX_EPOCH + Duration::from_secs(BLOCK_TIME),
                false,
                BLOCK_TIME - CLOCK_MARGIN,
            ),
            // Years ahead, outside the index: from where it says.
            (
                UNIX_EPOCH + Duration::from_secs(4_102_444_800),
                false,
                4_102_444_800 - CLOCK_MARGIN,
            ),
            // Years ahead, in the index: no later than the payment can be.
            (
                UNIX_EPOCH + Duration::from_secs(4_102_444_800),
                true,
                first_seen_at(NOW) + FIRST_SEEN_ROUNDING + CLOCK_MARGIN,
            ),
        ] {
            let mut fixture = fixture(shown, in_index);
            let quote = signed_quote_at(fixture.envelope.address(), timestamp);
            fixture.chain.receipts.push(receipt(
                [0x55; 32],
                BLOCK + 2,
                vec![payment_log(&quote, 0)],
            ));
            let mut listing = fixture.listing();
            listing.payment.quote = Some(encode_quote(&quote).unwrap());
            let Ok(Lookup::Quote {
                search_from,
                not_after,
                ..
            }) = payment_lookup(&listing)
            else {
                panic!("{timestamp:?}: not a quote lookup");
            };
            assert_eq!(search_from, expected, "{timestamp:?}");
            assert!(not_after.is_none_or(|latest| search_from <= latest));
            // And the payment is still found and checks out.
            let check = fixture.chain.check(&listing, &fixture.envelope, NOW);
            assert_eq!(
                check.map(|check| check.paid_at),
                Ok(Some(PaidAt {
                    block_number: BLOCK + 2,
                    log_index: 0
                })),
                "{timestamp:?}"
            );
        }
    }

    #[test]
    fn verifies_every_flags_byte_and_catches_tampering() {
        for flags in every_flags() {
            let shown = flags.shown;
            let fixture = fixture_flags(flags);
            let listing = fixture.listing();
            assert_eq!(listing.flags, flags);
            assert_eq!(listing.size, (!flags.withheld).then_some(30));
            let level = if shown.contains(PaymentField::Quote) {
                CheckLevel::Verified
            } else {
                CheckLevel::Reported
            };
            assert_eq!(fixture.verify(&listing), Ok(level), "{flags:?}");

            for field in shown.shown() {
                let mut tampered = listing.clone();
                tamper(&mut tampered, field, &fixture.unpaid_quote);
                let result = fixture.verify(&tampered);
                if detectable(shown, field) {
                    assert!(result.is_err(), "{field} changed, {flags:?}");
                } else {
                    assert_eq!(
                        result,
                        Ok(CheckLevel::Reported),
                        "{field} changed, {flags:?}"
                    );
                }
            }

            // Flipping a flag, or giving a withheld file a size, makes the
            // listing describe another envelope.
            let mismatch = Err(PaymentError::Malformed(ListingError::EnvelopeMismatch));
            let mut flipped = listing.clone();
            flipped.flags.withheld = !flags.withheld;
            flipped.size = (!flipped.flags.withheld).then_some(30);
            assert_eq!(fixture.verify(&flipped), mismatch, "{flags:?}");
            let mut moved = listing.clone();
            moved.flags.in_index = !flags.in_index;
            moved.first_seen = (moved.flags.in_index
                && !shown.contains(PaymentField::BlockTimestamp))
            .then_some(first_seen_at(NOW));
            assert_eq!(fixture.verify(&moved), mismatch, "{flags:?}");
        }
    }

    #[test]
    fn tampering_gives_the_right_error() {
        use PaymentField::*;
        let cases: [(&[PaymentField], PaymentField, PaymentError); 16] = [
            // With the quote.
            (&[TxHash, Quote], TxHash, PaymentError::NotFound),
            (
                &[TxHash, BlockNumber, Quote],
                BlockNumber,
                PaymentError::WrongBlock,
            ),
            (&[BlockNumber, Quote], BlockNumber, PaymentError::NotFound),
            (
                &[BlockTimestamp, Quote],
                BlockTimestamp,
                PaymentError::WrongTimestamp,
            ),
            (&[LogIndex, Quote], LogIndex, PaymentError::NotPaid),
            (&[TxHash, Quote], Quote, PaymentError::NotPaid),
            (&[Quote], Quote, PaymentError::NotFound),
            // With the tx hash and no quote.
            (&[TxHash], TxHash, PaymentError::NotFound),
            (
                &[TxHash, BlockNumber],
                BlockNumber,
                PaymentError::WrongBlock,
            ),
            (
                &[TxHash, BlockTimestamp],
                BlockTimestamp,
                PaymentError::WrongTimestamp,
            ),
            (&[TxHash, LogIndex], LogIndex, PaymentError::NotPaid),
            // With the block and log index.
            (
                &[BlockNumber, LogIndex],
                BlockNumber,
                PaymentError::NotFound,
            ),
            (&[BlockNumber, LogIndex], LogIndex, PaymentError::NotFound),
            (
                &[BlockNumber, LogIndex, BlockTimestamp],
                BlockTimestamp,
                PaymentError::WrongTimestamp,
            ),
            // With the block alone.
            (
                &[BlockNumber, BlockTimestamp],
                BlockNumber,
                PaymentError::WrongTimestamp,
            ),
            (
                &[BlockNumber, BlockTimestamp],
                BlockTimestamp,
                PaymentError::WrongTimestamp,
            ),
        ];
        for (shown, field, error) in cases {
            let fixture = fixture_with(shown);
            let mut listing = fixture.listing();
            tamper(&mut listing, field, &fixture.unpaid_quote);
            assert_eq!(
                fixture.verify(&listing),
                Err(error),
                "{field} changed, {shown:?} shown"
            );
        }
    }

    #[test]
    fn rejects_quotes_that_do_not_check_out() {
        let fixture = fixture(ShownFields::ALL, true);
        let listing = fixture.listing();
        let receipt = &fixture.chain.receipts[0];
        let time = block_time(BLOCK);
        let verify = |listing: &Listing, vault: &[u8; 20]| {
            verify_now(listing, &fixture.envelope, Some(receipt), time, vault)
        };
        assert_eq!(verify(&listing, &VAULT), Ok(CheckLevel::Verified));

        let mut elsewhere = listing.clone();
        elsewhere.payment.quote = Some(encode_quote(&signed_quote([5; 32])).unwrap());
        assert_eq!(verify(&elsewhere, &VAULT), Err(PaymentError::WrongContent));

        let mut forged = decode_quote(&fixture.payment.quote).unwrap();
        forged.price = Amount::from(1u64);
        let mut forged_listing = listing.clone();
        forged_listing.payment.quote = Some(encode_quote(&forged).unwrap());
        assert_eq!(
            verify(&forged_listing, &VAULT),
            Err(PaymentError::BadSignature)
        );

        let mut garbled = listing.clone();
        garbled.payment.quote = Some(vec![0xc1]);
        assert!(matches!(
            verify(&garbled, &VAULT),
            Err(PaymentError::BadQuote(_))
        ));
        assert!(matches!(
            payment_lookup(&{
                let mut garbled = garbled.clone();
                garbled.payment.tx_hash = None;
                garbled.flags.shown = garbled.flags.shown.without(PaymentField::TxHash);
                garbled
            }),
            Err(PaymentError::BadQuote(_))
        ));

        assert_eq!(verify(&listing, &[0x11; 20]), Err(PaymentError::NotPaid));
    }

    #[test]
    fn quotes_must_be_canonical() {
        let fixture = fixture_with(&[PaymentField::Quote]);
        let listing = fixture.listing();
        let canonical = listing.payment.quote.clone().unwrap();
        let quote = decode_quote(&canonical).unwrap();
        assert_eq!(encode_quote(&quote).unwrap(), canonical);

        let mut trailing = canonical.clone();
        trailing.push(0);
        let named = rmp_serde::to_vec_named(&quote).unwrap();
        for other in [trailing, named] {
            assert_ne!(other, canonical);
            // The same quote, in other bytes.
            assert_eq!(
                rmp_serde::from_slice::<PaymentQuote>(&other).unwrap(),
                quote
            );
            let not_canonical = PaymentError::BadQuote("not canonical".into());
            assert_eq!(decode_quote(&other).unwrap_err(), not_canonical);
            let mut copy = listing.clone();
            copy.payment.quote = Some(other);
            assert_eq!(payment_lookup(&copy), Err(not_canonical.clone()));
            assert_eq!(fixture.verify(&copy), Err(not_canonical));
        }
        assert_eq!(fixture.verify(&listing), Ok(CheckLevel::Verified));
    }

    #[test]
    fn rejects_receipts_that_do_not_check_out() {
        let time = block_time(BLOCK);
        for shown in [
            ShownFields::ALL,
            ShownFields::ALL.without(PaymentField::Quote),
            ShownFields::NONE
                .with(PaymentField::BlockNumber)
                .with(PaymentField::LogIndex)
                .with(PaymentField::BlockTimestamp),
        ] {
            let fixture = fixture(shown, true);
            let listing = fixture.listing();
            let check = |receipt: &PaymentReceipt, time| {
                verify_now(&listing, &fixture.envelope, Some(receipt), time, &VAULT)
            };
            let good = &fixture.chain.receipts[0];
            assert!(check(good, time).is_ok());

            let mut failed = good.clone();
            failed.success = false;
            assert_eq!(check(&failed, time), Err(PaymentError::Failed), "{shown:?}");

            let mut zero_amount = good.clone();
            zero_amount.logs[1].topics[2] = [0; 32];
            assert_eq!(
                check(&zero_amount, time),
                Err(PaymentError::NotPaid),
                "{shown:?}"
            );

            let mut elsewhere = good.clone();
            elsewhere.logs[1].address = [0x12; 20];
            assert_eq!(
                check(&elsewhere, time),
                Err(PaymentError::NotPaid),
                "{shown:?}"
            );

            let mut other_event = good.clone();
            other_event.logs[1].topics[0] = [0x13; 32];
            assert_eq!(
                check(&other_event, time),
                Err(PaymentError::NotPaid),
                "{shown:?}"
            );

            assert_eq!(
                verify_now(&listing, &fixture.envelope, None, time, &VAULT),
                Err(PaymentError::NotFound),
                "{shown:?}"
            );
            assert_eq!(check(good, None), Err(PaymentError::NotFound), "{shown:?}");
        }

        // Without the timestamp shown, it is needed only to check
        // first_seen, which only listings in the index have.
        let hidden = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        for in_index in [false, true] {
            let fixture = fixture(hidden, in_index);
            let listing = fixture.listing();
            let receipt = &fixture.chain.receipts[0];
            let without = verify_now(&listing, &fixture.envelope, Some(receipt), None, &VAULT);
            let with = verify_now(&listing, &fixture.envelope, Some(receipt), time, &VAULT);
            assert_eq!(with, Ok(CheckLevel::Verified));
            if in_index {
                assert_eq!(without, Err(PaymentError::NotFound));
            } else {
                assert_eq!(without, Ok(CheckLevel::Verified));
            }
        }

        // The block alone needs its timestamp, to show the block exists.
        for in_index in [false, true] {
            let fixture = fixture(ShownFields::NONE.with(PaymentField::BlockNumber), in_index);
            let block_only = fixture.listing();
            assert_eq!(
                verify_now(&block_only, &fixture.envelope, None, None, &VAULT),
                Err(PaymentError::NotFound)
            );
            assert_eq!(
                verify_now(&block_only, &fixture.envelope, None, Some(1), &VAULT),
                Ok(CheckLevel::Reported)
            );
        }
    }

    #[test]
    fn first_seen_cannot_be_before_the_payment() {
        let paid_at = block_time(BLOCK).unwrap();
        // The earliest an honest node records: its clock CLOCK_MARGIN behind
        // the chain's.
        let earliest = first_seen_at(paid_at - CLOCK_MARGIN);
        let too_early = [
            0,
            1_000 * FIRST_SEEN_ROUNDING,
            earliest - FIRST_SEEN_ROUNDING,
        ];
        for flags in dated_by_first_seen() {
            let shown = flags.shown;
            let fixture = fixture_flags(flags);
            let honest = fixture.listing();
            let lookup = payment_lookup(&honest).unwrap();
            let (receipt, timestamp) = fixture
                .chain
                .fetch(lookup)
                .into_iter()
                .next()
                .unwrap_or((None, None));
            let with_first_seen = |first_seen| Listing {
                first_seen: Some(first_seen),
                ..honest.clone()
            };
            let check_at = |first_seen, now| {
                verify_listing(
                    &with_first_seen(first_seen),
                    &fixture.envelope,
                    receipt.as_ref(),
                    timestamp,
                    &VAULT,
                    now,
                )
                .map(|check| check.level)
            };
            let check = |first_seen| check_at(first_seen, NOW);
            let level = if shown.contains(PaymentField::Quote) {
                CheckLevel::Verified
            } else {
                CheckLevel::Reported
            };
            assert_eq!(check(honest.first_seen.unwrap()), Ok(level), "{shown:?}");
            assert_eq!(check(earliest), Ok(level), "{shown:?}");
            // A node can record it any time later, checked later.
            let later = paid_at + 86_400;
            assert_eq!(check_at(first_seen_at(later), later), Ok(level));

            let located = lookup != Lookup::Nothing;
            for first_seen in too_early {
                if located {
                    assert_eq!(
                        check(first_seen),
                        Err(PaymentError::FirstSeenTooEarly),
                        "{shown:?}"
                    );
                    // Searching only up to its latest payment time, a caller
                    // may not find the payment at all.
                    assert!(fixture.verify(&with_first_seen(first_seen)).is_err());
                } else {
                    // Nothing locates the payment, so nothing bounds it.
                    assert_eq!(check(first_seen), Ok(level), "{shown:?}");
                }
            }
        }
    }

    #[test]
    fn a_quote_paid_twice_still_verifies() {
        // The quote and time are shown, the tx hash and block hidden, so the
        // quote's hash finds the payment.
        let shown = ShownFields::NONE
            .with(PaymentField::Quote)
            .with(PaymentField::BlockTimestamp);
        let mut fixture = fixture(shown, true);
        let quote = decode_quote(&fixture.payment.quote).unwrap();
        // Someone pays the same quote again, later, as upstream's vault
        // allows.
        fixture.chain.receipts.push(receipt(
            [0x99; 32],
            BLOCK + 500,
            vec![payment_log(&quote, 1)],
        ));
        let listing = fixture.listing();
        let found = fixture.chain.fetch(payment_lookup(&listing).unwrap());
        let results: Vec<_> = found
            .iter()
            .map(|(receipt, time)| {
                verify_now(&listing, &fixture.envelope, receipt.as_ref(), *time, &VAULT)
            })
            .collect();
        assert_eq!(
            results,
            [Ok(CheckLevel::Verified), Err(PaymentError::WrongTimestamp)]
        );
        assert_eq!(fixture.verify(&listing), Ok(CheckLevel::Verified));
        fixture.chain.receipts.reverse();
        assert_eq!(fixture.verify(&listing), Ok(CheckLevel::Verified));
    }

    #[test]
    fn a_tx_hash_without_the_quote_accepts_any_vault_payment_in_the_tx() {
        // The receipt also pays another chunk at index 3. Without the quote,
        // nothing tells the two apart: the listing is only reported.
        let fixture = fixture_with(&[PaymentField::TxHash, PaymentField::LogIndex]);
        let mut listing = fixture.listing();
        listing.payment.log_index = Some(3);
        assert_eq!(fixture.verify(&listing), Ok(CheckLevel::Reported));

        let fixture = fixture_with(&[
            PaymentField::TxHash,
            PaymentField::LogIndex,
            PaymentField::Quote,
        ]);
        let mut with_quote = fixture.listing();
        with_quote.payment.log_index = Some(3);
        assert_eq!(fixture.verify(&with_quote), Err(PaymentError::NotPaid));
    }

    #[test]
    fn rejects_malformed_listings() {
        let fixture = fixture_with(&[PaymentField::TxHash]);
        let mut listing = fixture.listing();
        listing.payment.block_number = Some(BLOCK);
        let error =
            PaymentError::Malformed(ListingError::HiddenFieldPresent(PaymentField::BlockNumber));
        assert_eq!(payment_lookup(&listing), Err(error.clone()));
        assert_eq!(
            verify_now(
                &listing,
                &fixture.envelope,
                Some(&fixture.chain.receipts[0]),
                None,
                &VAULT
            ),
            Err(error)
        );
        listing.payment.block_number = None;
        listing.first_seen = None;
        assert_eq!(
            fixture.verify(&listing),
            Err(PaymentError::Malformed(ListingError::MissingFirstSeen))
        );
    }

    #[test]
    fn nothing_shown_is_reported_unchecked() {
        for in_index in [false, true] {
            let fixture = fixture(ShownFields::NONE, in_index);
            let listing = fixture.listing();
            assert_eq!(payment_lookup(&listing), Ok(Lookup::Nothing));
            assert_eq!(
                verify_now(&listing, &fixture.envelope, None, None, &VAULT),
                Ok(CheckLevel::Reported)
            );
        }
    }

    #[test]
    fn the_listing_must_match_its_envelope() {
        // An unlisted file showing only its quote, which one node can serve.
        let fixture = fixture(ShownFields::NONE.with(PaymentField::Quote), false);
        let listing = fixture.listing();
        assert_eq!(fixture.verify(&listing), Ok(CheckLevel::Verified));
        let mismatch = Err(PaymentError::Malformed(ListingError::EnvelopeMismatch));

        // Pushed into the index, with the first_seen that needs.
        let mut indexed = listing.clone();
        indexed.flags.in_index = true;
        indexed.first_seen = Some(first_seen_at(NOW));
        assert_eq!(indexed.validate(), Ok(()));
        assert_eq!(fixture.verify(&indexed), mismatch);

        // A forged name, content type or size.
        let mut renamed = listing.clone();
        renamed.metadata.name = Some("invoice.pdf".into());
        assert_eq!(fixture.verify(&renamed), mismatch);
        let mut retyped = listing.clone();
        retyped.metadata.content_type = Some("application/pdf".into());
        assert_eq!(fixture.verify(&retyped), mismatch);
        let mut stripped = listing.clone();
        stripped.metadata = Metadata::default();
        assert_eq!(fixture.verify(&stripped), mismatch);
        let mut resized = listing.clone();
        resized.size = Some(1);
        assert_eq!(fixture.verify(&resized), mismatch);

        // Both at once.
        let mut both = indexed.clone();
        both.metadata.name = Some("invoice.pdf".into());
        assert_eq!(fixture.verify(&both), mismatch);

        // Hidden fields a storing node knows, shown.
        let mut leaked = listing.clone();
        leaked.flags.shown = ShownFields::ALL;
        leaked.payment = fixture.payment.mask(ShownFields::ALL);
        assert_eq!(leaked.validate(), Ok(()));
        assert_eq!(fixture.verify(&leaked), mismatch);

        // Against another file's envelope.
        let other = fixture_with(&[PaymentField::Quote]);
        assert_eq!(other.chain.verify(&listing, &other.envelope), mismatch);
    }

    #[test]
    fn verified_listings_say_where_the_quote_was_paid() {
        let paid_at = PaidAt {
            block_number: BLOCK,
            log_index: LOG_INDEX,
        };
        for flags in every_flags() {
            let fixture = fixture_flags(flags);
            let check = fixture
                .chain
                .check(&fixture.listing(), &fixture.envelope, NOW);
            if flags.shown.contains(PaymentField::Quote) {
                // Also when the listing hides the block and log index.
                assert_eq!(
                    check,
                    Ok(ListingCheck {
                        level: CheckLevel::Verified,
                        paid_at: Some(paid_at),
                    }),
                    "{flags:?}"
                );
            } else {
                assert_eq!(
                    check,
                    Ok(ListingCheck {
                        level: CheckLevel::Reported,
                        paid_at: None,
                    }),
                    "{flags:?}"
                );
            }
        }
    }

    /// The listing a node that paid a quote of its own for `fixture`'s
    /// address, in block `block`, serves: verified like the upload's.
    fn self_paid(fixture: &mut Fixture, block: u64) -> (Listing, EnvelopeProof, PaymentReceipt) {
        let address = fixture.envelope.address();
        let own = self_issued_quote(address, [0xaa; 20]);
        let tx = [0x31; 32];
        let theirs = receipt(tx, block, vec![payment_log(&own, 0)]);
        fixture.chain.receipts.push(theirs.clone());
        let payment = find_payment(
            &address,
            std::slice::from_ref(&own),
            &theirs,
            block_time(block).unwrap(),
            &VAULT,
        )
        .unwrap();
        let listing = Listing::new(&fixture.envelope, &payment, NOW);
        let proof = EnvelopeProof::new(&fixture.envelope, tx, &own).unwrap();
        (listing, proof, theirs)
    }

    /// Check each of `groups` as a caller does, against the chain, with
    /// `first_seen` from `nearest`, and choose among the verified ones.
    fn choose(
        fixture: &Fixture,
        groups: &[crate::MergedListing<u8>],
        nearest: &[u8],
    ) -> Option<ChosenVerified<Listing>> {
        let checked: Vec<_> = groups
            .iter()
            .filter_map(|group| {
                let (listing, check) = fixture.check_group(group, nearest).ok()?;
                Some((group, listing, check))
            })
            .collect();
        choose_verified(checked, nearest)
    }

    /// The sets that show the quote the tests of [`choose_verified`] use: the
    /// quote found by tx hash, by its own hash, with the time or without.
    fn quote_shown_sets() -> [ShownFields; 4] {
        let quote = ShownFields::NONE.with(PaymentField::Quote);
        [
            ShownFields::ALL,
            quote,
            quote.with(PaymentField::TxHash),
            quote.with(PaymentField::BlockTimestamp),
        ]
    }

    #[test]
    fn a_quoting_node_can_pay_first_but_the_close_group_decides() {
        // A node asked to quote for the envelope learns its address before
        // the uploader pays. It signs a quote of its own, pays it to itself
        // in an earlier block, and serves the listing built from that once
        // the envelope is stored. Someone who fetches the envelope later can
        // do the same in a later block. Both verify.
        let nearest: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
        for shown in quote_shown_sets() {
            for (in_index, withheld) in [(false, false), (true, false), (true, true)] {
                for forged_block in [BLOCK - 1, BLOCK + 7] {
                    let flags = Flags {
                        shown,
                        in_index,
                        withheld,
                    };
                    let mut fixture = fixture_flags(flags);
                    let honest = fixture.listing();
                    let (forged, forged_proof, forged_receipt) =
                        self_paid(&mut fixture, forged_block);
                    assert!(!forged.eq_apart_from_first_seen(&honest));
                    let honest_check = fixture.chain.check(&honest, &fixture.envelope, NOW);
                    let forged_check = fixture.chain.check(&forged, &fixture.envelope, NOW);
                    let honest_paid = PaidAt {
                        block_number: BLOCK,
                        log_index: LOG_INDEX,
                    };
                    let forged_paid = PaidAt {
                        block_number: forged_block,
                        log_index: 0,
                    };
                    let verified = |paid_at| {
                        Ok(ListingCheck {
                            level: CheckLevel::Verified,
                            paid_at: Some(paid_at),
                        })
                    };
                    assert_eq!(honest_check, verified(honest_paid), "{flags:?}");
                    assert_eq!(forged_check, verified(forged_paid), "{flags:?}");

                    // Six of the seven nearest recorded the upload's payment
                    // from its PUT; the forger serves its own. The close group
                    // decides, in whichever order the copies come.
                    let mut copies: Vec<(u8, Listing)> =
                        (1..=6).map(|peer| (peer, honest.clone())).collect();
                    copies.insert(0, (7, forged.clone()));
                    for _ in 0..2 {
                        let groups = merge_copies(copies.clone());
                        assert_eq!(groups.len(), 2);
                        let chosen = choose(&fixture, &groups, &nearest).unwrap();
                        assert_eq!(
                            chosen,
                            ChosenVerified {
                                item: honest.clone(),
                                paid_at: honest_paid,
                                count: 6,
                                quorum: true,
                            },
                            "{flags:?}, forged in block {forged_block}"
                        );
                        copies.reverse();
                    }

                    // A node repairing the listing asks four peers, the
                    // forger among them: three of four is a quorum.
                    let asked = [2, 4, 6, 7];
                    let groups = merge_copies(
                        copies
                            .iter()
                            .filter(|(peer, _)| asked.contains(peer))
                            .cloned(),
                    );
                    let chosen = choose(&fixture, &groups, &asked).unwrap();
                    assert_eq!((chosen.item, chosen.quorum), (honest.clone(), true));

                    // With only three honest copies of seven heard, neither
                    // has a quorum: the earliest payment is a fallback, and
                    // says so. Here the forger's, when it paid first.
                    let groups = merge_copies(
                        copies
                            .iter()
                            .filter(|(peer, _)| [1, 2, 3, 7].contains(peer))
                            .cloned(),
                    );
                    let chosen = choose(&fixture, &groups, &nearest).unwrap();
                    assert!(!chosen.quorum);
                    let earliest = if forged_block < BLOCK {
                        (forged.clone(), forged_paid, 1)
                    } else {
                        (honest.clone(), honest_paid, 3)
                    };
                    assert_eq!((chosen.item, chosen.paid_at, chosen.count), earliest);

                    // The forger's proof checks out too, paid earlier or
                    // later: neither proof outranks the other.
                    let proven = check_proof(
                        &forged_proof,
                        &forged_receipt,
                        block_time(forged_block).unwrap(),
                        &VAULT,
                    )
                    .unwrap();
                    assert_eq!(proven.paid_at(), forged_paid);
                }
            }
        }
    }

    #[test]
    fn three_of_the_nearest_cannot_change_a_listing() {
        let nearest: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
        let needed = quorum_needed(nearest.len());

        // Without the quote: three of the nearest serve a changed listing,
        // pointing at another vault payment in the same transaction, which
        // checks out as far as anything can; four serve the upload's. A node
        // outside the nearest serves a third that nobody else has.
        let reported = fixture_with(&[PaymentField::TxHash, PaymentField::LogIndex]);
        let honest = reported.listing();
        let mut changed = honest.clone();
        changed.payment.log_index = Some(3);
        assert_eq!(reported.verify(&changed), Ok(CheckLevel::Reported));
        let mut alone = honest.clone();
        alone.payment.log_index = Some(9);
        let mut copies: Vec<(u8, Listing)> = (1..=4).map(|peer| (peer, honest.clone())).collect();
        copies.extend((5..=7).map(|peer| (peer, changed.clone())));
        copies.push((8, alone));
        let groups = merge_copies(copies);
        assert_eq!(groups.len(), 3);
        let counted: Vec<(Listing, usize)> = groups
            .iter()
            .filter_map(|group| {
                let (listing, check) = reported.check_group(group, &nearest).ok()?;
                assert_eq!(check.level, CheckLevel::Reported);
                Some((listing, group.count_among(&nearest)))
            })
            .collect();
        // The one only a node outside the nearest has gets no first_seen
        // from them, and doesn't check out anyway; the changed one does, but
        // only the upload's has a quorum.
        assert_eq!(counted, [(honest.clone(), 4), (changed, 3)]);
        let kept: Vec<&Listing> = counted
            .iter()
            .filter(|(_, count)| *count >= needed)
            .map(|(listing, _)| listing)
            .collect();
        assert_eq!(kept, [&honest]);

        // With the quote: three serve a forger's copy, paid later; four the
        // upload's, which is kept.
        let mut fixture = fixture(ShownFields::ALL, true);
        let honest = fixture.listing();
        let (forged, _, _) = self_paid(&mut fixture, BLOCK + 3);
        let mut copies: Vec<(u8, Listing)> = (1..=4).map(|peer| (peer, honest.clone())).collect();
        copies.extend((5..=7).map(|peer| (peer, forged.clone())));
        let groups = merge_copies(copies);
        let chosen = choose(&fixture, &groups, &nearest).unwrap();
        assert_eq!(
            (chosen.item, chosen.count, chosen.quorum),
            (honest, 4, true)
        );
        // A verified listing that one node alone serves is still kept, as
        // a fallback, when nothing else is verified.
        let groups = merge_copies([(7, forged.clone())]);
        let chosen = choose(&fixture, &groups, &nearest).unwrap();
        assert_eq!(
            (chosen.item, chosen.count, chosen.quorum),
            (forged, 1, false)
        );
    }

    #[test]
    fn choose_verified_prefers_a_quorum_then_the_earliest() {
        let listing = fixture(ShownFields::ALL, true).listing();
        let group = |peers: &[u8]| merge_copies(peers.iter().map(|&peer| (peer, listing.clone())));
        let at = |block_number| ListingCheck {
            level: CheckLevel::Verified,
            paid_at: Some(PaidAt {
                block_number,
                log_index: 0,
            }),
        };
        let reported = ListingCheck {
            level: CheckLevel::Reported,
            paid_at: None,
        };
        let four = group(&[1, 2, 3, 4]);
        let three = group(&[5, 6, 7]);
        let one = group(&[7]);
        let nearest = [1, 2, 3, 4, 5, 6, 7];
        assert_eq!(choose_verified::<u8, u8>([], &nearest), None);
        assert_eq!(choose_verified([(&four[0], 'r', reported)], &nearest), None);
        // A quorum beats an earlier payment.
        let chosen = choose_verified(
            [
                (&one[0], 'a', at(5)),
                (&four[0], 'b', at(9)),
                (&three[0], 'c', at(1)),
            ],
            &nearest,
        );
        assert_eq!(
            chosen,
            Some(ChosenVerified {
                item: 'b',
                paid_at: PaidAt {
                    block_number: 9,
                    log_index: 0
                },
                count: 4,
                quorum: true
            })
        );
        // Reported checks never count, even with a quorum.
        let chosen = choose_verified(
            [
                (&four[0], 'b', reported),
                (&three[0], 'c', at(3)),
                (&one[0], 'a', at(2)),
            ],
            &nearest,
        )
        .unwrap();
        assert_eq!((chosen.item, chosen.quorum), ('a', false));
        // More than seven nearest: two groups can both have four. The
        // earlier payment breaks the tie, then the first.
        let wide = [1, 2, 3, 4, 5, 6, 7, 8];
        let other = group(&[5, 6, 7, 8]);
        let chosen =
            choose_verified([(&four[0], 'b', at(9)), (&other[0], 'd', at(8))], &wide).unwrap();
        assert_eq!((chosen.item, chosen.quorum), ('d', true));
        let chosen =
            choose_verified([(&four[0], 'b', at(8)), (&other[0], 'd', at(8))], &wide).unwrap();
        assert_eq!(chosen.item, 'b');
        // No nearest nodes known: nothing has a quorum.
        let chosen = choose_verified([(&four[0], 'b', at(9))], &[]).unwrap();
        assert_eq!((chosen.count, chosen.quorum), (0, false));
    }

    #[test]
    fn earliest_verified_ignores_reported_listings() {
        let reported = ListingCheck {
            level: CheckLevel::Reported,
            paid_at: None,
        };
        let at = |block_number, log_index| ListingCheck {
            level: CheckLevel::Verified,
            paid_at: Some(PaidAt {
                block_number,
                log_index,
            }),
        };
        assert_eq!(earliest_verified::<u8>([]), None);
        assert_eq!(earliest_verified([(1, reported)]), None);
        // A Reported check never wins, even one that claims a payment.
        let claims = ListingCheck {
            level: CheckLevel::Reported,
            paid_at: Some(PaidAt {
                block_number: 0,
                log_index: 0,
            }),
        };
        assert_eq!(
            earliest_verified([(1, claims), (2, at(9, 9))]).map(|(item, _)| item),
            Some(2)
        );
        // Block first, then log index; the first of equals.
        let checks = [
            (1, at(10, 5)),
            (2, at(9, 7)),
            (3, reported),
            (4, at(9, 6)),
            (5, at(9, 6)),
        ];
        assert_eq!(
            earliest_verified(checks),
            Some((
                4,
                PaidAt {
                    block_number: 9,
                    log_index: 6
                }
            ))
        );
    }

    #[test]
    fn a_quote_paid_twice_counts_from_its_first_payment() {
        // With the time hidden, a later payment of the same quote checks out
        // too; the first is the one kept, whatever order the search gives.
        let shown = ShownFields::NONE.with(PaymentField::Quote);
        for withheld in [false, true] {
            let mut fixture = fixture_flags(Flags {
                shown,
                in_index: true,
                withheld,
            });
            let quote = decode_quote(&fixture.payment.quote).unwrap();
            fixture.chain.receipts.insert(
                0,
                receipt([0x99; 32], BLOCK + 500, vec![payment_log(&quote, 1)]),
            );
            let listing = fixture.listing();
            let mut found = fixture.chain.fetch(payment_lookup(&listing).unwrap());
            assert_eq!(found.len(), 2);
            assert!(found.iter().all(|(receipt, time)| {
                verify_listing(
                    &listing,
                    &fixture.envelope,
                    receipt.as_ref(),
                    *time,
                    &VAULT,
                    NOW,
                )
                .is_ok_and(|check| check.level == CheckLevel::Verified)
            }));
            let first = Ok(ListingCheck {
                level: CheckLevel::Verified,
                paid_at: Some(PaidAt {
                    block_number: BLOCK,
                    log_index: LOG_INDEX,
                }),
            });
            for _ in 0..2 {
                assert_eq!(
                    verify_listing_receipts(&listing, &fixture.envelope, &found, &VAULT, NOW),
                    first
                );
                // A backwards search finds the later one first.
                found.reverse();
            }
        }
    }

    #[test]
    fn checks_against_everything_a_lookup_found() {
        let verify = |fixture: &Fixture, listing: &Listing, fetched: &[Fetched]| {
            verify_listing_receipts(listing, &fixture.envelope, fetched, &VAULT, NOW)
                .map(|check| check.level)
        };

        // Nothing found: not on chain, unless nothing was needed.
        for flags in every_flags() {
            let fixture = fixture_flags(flags);
            let listing = fixture.listing();
            let expected = if payment_lookup(&listing) == Ok(Lookup::Nothing) {
                Ok(CheckLevel::Reported)
            } else {
                Err(PaymentError::NotFound)
            };
            assert_eq!(verify(&fixture, &listing, &[]), expected, "{flags:?}");
            assert_eq!(
                verify(&fixture, &listing, &[(None, None)]),
                expected,
                "{flags:?}"
            );
        }

        let fixture = fixture_with(&[PaymentField::Quote, PaymentField::BlockTimestamp]);
        let listing = fixture.listing();
        let good: Fetched = (Some(fixture.chain.receipts[0].clone()), block_time(BLOCK));
        let mut unpaid_receipt = fixture.chain.receipts[0].clone();
        unpaid_receipt.logs.clear();
        let unpaid: Fetched = (Some(unpaid_receipt), block_time(BLOCK));
        let wrong_time: Fetched = (Some(fixture.chain.receipts[0].clone()), Some(1));
        let missing: Fetched = (None, None);

        // One receipt that checks out is enough, wherever it comes.
        for fetched in [
            vec![good.clone()],
            vec![unpaid.clone(), good.clone()],
            vec![good.clone(), wrong_time.clone(), missing.clone()],
            vec![missing.clone(), unpaid.clone(), good.clone()],
        ] {
            assert_eq!(
                verify(&fixture, &listing, &fetched),
                Ok(CheckLevel::Verified)
            );
        }
        // Otherwise the first error that says something was found and
        // disagrees, then not found.
        assert_eq!(
            verify(
                &fixture,
                &listing,
                &[missing.clone(), unpaid.clone(), wrong_time.clone()]
            ),
            Err(PaymentError::NotPaid)
        );
        assert_eq!(
            verify(&fixture, &listing, &[wrong_time.clone(), unpaid.clone()]),
            Err(PaymentError::WrongTimestamp)
        );
        assert_eq!(
            verify(&fixture, &listing, &[missing.clone(), missing]),
            Err(PaymentError::NotFound)
        );
        // A malformed listing fails whatever was found.
        let mut malformed = listing.clone();
        malformed.payment.tx_hash = Some(TX);
        assert!(matches!(
            verify(&fixture, &malformed, &[good]),
            Err(PaymentError::Malformed(_))
        ));
        assert!(matches!(
            verify(&fixture, &malformed, &[]),
            Err(PaymentError::Malformed(_))
        ));

        // A listing without the quote: the one receipt it is checked
        // against.
        let fixture = fixture_with(&[PaymentField::TxHash]);
        let listing = fixture.listing();
        let fetched = fixture.chain.fetch(payment_lookup(&listing).unwrap());
        assert_eq!(fetched.len(), 1);
        assert_eq!(
            verify(&fixture, &listing, &fetched),
            Ok(CheckLevel::Reported)
        );
    }

    #[test]
    fn quote_timestamps_are_whole_seconds() {
        let fixture = fixture(ShownFields::ALL, true);
        let address = fixture.envelope.address();
        let quote = decode_quote(&fixture.payment.quote).unwrap();
        // A node's clock gives a fraction of a second, which its signature and
        // hash don't cover.
        let fraction = with_nanos(&quote);
        assert_ne!(fraction, quote);
        assert_eq!(fraction.hash(), quote.hash());
        assert!(verify_quote_signature(&fraction));
        let fraction_bytes = rmp_serde::to_vec(&fraction).unwrap();
        assert_ne!(fraction_bytes, fixture.payment.quote);

        // Found at upload with the fraction, it is recorded without it.
        let receipt = &fixture.chain.receipts[0];
        let found = find_payment(
            &address,
            std::slice::from_ref(&fraction),
            receipt,
            BLOCK_TIME,
            &VAULT,
        )
        .unwrap();
        assert_eq!(found.quote, fixture.payment.quote);
        assert_eq!(encode_quote(&fraction).unwrap(), fixture.payment.quote);

        // Carried with it, it is refused: one paid quote has one encoding.
        let not_canonical = PaymentError::BadQuote("not canonical".into());
        assert_eq!(decode_quote(&fraction_bytes), Err(not_canonical.clone()));
        let mut copy = fixture.listing();
        copy.payment.quote = Some(fraction_bytes.clone());
        assert_eq!(fixture.verify(&copy), Err(not_canonical.clone()));
        let proof = EnvelopeProof::new(&fixture.envelope, TX, &fraction).unwrap();
        assert_eq!(proof.quote, fixture.payment.quote);
        assert!(check_proof(&proof, receipt, BLOCK_TIME, &VAULT).is_ok());
        let mut fraction_proof = proof;
        fraction_proof.quote = fraction_bytes.clone();
        assert_eq!(
            check_proof(&fraction_proof, receipt, BLOCK_TIME, &VAULT).unwrap_err(),
            crate::ProofError::Payment(not_canonical)
        );

        // A version 1 record of the quote, with its fraction, converts to the
        // whole-second encoding.
        let old = PaymentV1 {
            tx_hash: TX,
            block_number: BLOCK,
            block_timestamp: BLOCK_TIME,
            log_index: LOG_INDEX,
            quote: fraction_bytes,
        };
        assert_eq!(Payment::from(old), fixture.payment);
    }

    #[test]
    fn first_seen_in_the_future_is_refused() {
        let future = Err(PaymentError::Malformed(ListingError::TimeInFuture));
        for flags in dated_by_first_seen() {
            let shown = flags.shown;
            let fixture = fixture_flags(flags);
            let honest = fixture.listing();
            assert!(fixture.verify(&honest).is_ok(), "{shown:?}");
            // Dated in 2100, to sit at the top of a newest-first index.
            let mut pinned = honest.clone();
            pinned.first_seen = Some(first_seen_at(4_102_444_800));
            assert_eq!(fixture.verify(&pinned), future, "{shown:?}");
            assert_eq!(
                fixture
                    .chain
                    .check(&pinned, &fixture.envelope, 4_102_444_800),
                fixture.chain.check(&honest, &fixture.envelope, NOW),
                "{shown:?}"
            );
            // An old listing dated now, checked at a time it couldn't have
            // been recorded yet.
            assert_eq!(
                fixture
                    .chain
                    .check(&honest, &fixture.envelope, NOW - 3 * 3_600)
                    .map(|check| check.level),
                future
            );
            // Recorded by a node passing its clock in milliseconds.
            let millis = Listing::new(&fixture.envelope, &fixture.payment, NOW * 1_000);
            assert_eq!(fixture.verify(&millis), future, "{shown:?}");
        }
    }

    #[test]
    fn a_shown_timestamp_in_the_future_is_refused() {
        let future = Err(PaymentError::Malformed(ListingError::TimeInFuture));
        let timestamp = ShownFields::NONE.with(PaymentField::BlockTimestamp);
        // Nothing locates the payment: the bound is the only check on the
        // listing's time, which is its place in the index.
        for shown in [timestamp, timestamp.with(PaymentField::LogIndex)] {
            for in_index in [false, true] {
                for withheld in [false, true] {
                    let flags = Flags {
                        shown,
                        in_index,
                        withheld,
                    };
                    let fixture = fixture_flags(flags);
                    let honest = fixture.listing();
                    assert_eq!(payment_lookup(&honest), Ok(Lookup::Nothing));
                    assert_eq!(fixture.verify(&honest), Ok(CheckLevel::Reported));
                    for pinned in [NOW + CLOCK_MARGIN + 1, 4_102_444_800, u64::MAX] {
                        let mut moved = honest.clone();
                        moved.payment.block_timestamp = Some(pinned);
                        assert_eq!(moved.key().time, pinned);
                        assert_eq!(fixture.verify(&moved), future, "{flags:?}, {pinned}");
                    }
                    // Up to the margin ahead of the checker's clock passes,
                    // and any earlier time can't be checked here: it rests
                    // on the nodes nearest the address.
                    for unchecked in [NOW + CLOCK_MARGIN, 0] {
                        let mut moved = honest.clone();
                        moved.payment.block_timestamp = Some(unchecked);
                        assert_eq!(fixture.verify(&moved), Ok(CheckLevel::Reported));
                    }
                }
            }
        }
        // Where the payment is located, a time in the future is refused
        // before the chain is asked.
        let fixture = fixture(ShownFields::ALL, true);
        let mut moved = fixture.listing();
        moved.payment.block_timestamp = Some(u64::MAX);
        assert_eq!(fixture.verify(&moved), future);
    }

    /// Copies of `listing` from peers 1 to `values.len()`, each with its own
    /// `first_seen`.
    fn copies_with_first_seen(listing: &Listing, values: &[u64]) -> Vec<(u8, Listing)> {
        (1..)
            .zip(values)
            .map(|(peer, &first_seen)| {
                (
                    peer,
                    Listing {
                        first_seen: Some(first_seen),
                        ..listing.clone()
                    },
                )
            })
            .collect()
    }

    #[test]
    fn values_out_of_bounds_neither_fail_nor_move_first_seen() {
        let nearest: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
        let backdated = 0;
        let pinned = first_seen_at(4_102_444_800);
        for flags in dated_by_first_seen() {
            let fixture = fixture_flags(flags);
            let honest = fixture.listing();
            let h = honest.first_seen.unwrap();
            let lookup = payment_lookup(&honest).unwrap();
            let located = lookup != Lookup::Nothing;
            let level = fixture.verify(&honest).unwrap();
            for values in [
                // One of the seven offline, and three of the six answering
                // send a bad value.
                vec![backdated, backdated, backdated, h, h, h],
                vec![h, pinned, h, pinned, h, pinned],
                // Only two answer, one of them lying.
                vec![backdated, h],
                vec![pinned, h],
                // A mix, with a later honest hour from a node that stored it
                // after the turn of the hour.
                vec![
                    backdated,
                    pinned,
                    h,
                    h + FIRST_SEEN_ROUNDING,
                    backdated,
                    pinned,
                ],
            ] {
                let groups = merge_copies(copies_with_first_seen(&honest, &values));
                assert_eq!(groups.len(), 1);
                // The values in bounds: never one in the future, and none
                // before the payment where anything locates it.
                let mut in_bounds: Vec<u64> = values
                    .iter()
                    .copied()
                    .filter(|&value| value != pinned && (!located || value != backdated))
                    .collect();
                in_bounds.sort_unstable();
                let expected = in_bounds[in_bounds.len() / 2];
                if values.len() < 6 || values.iter().filter(|&&v| v == h).count() == 3 {
                    assert_eq!(expected, h, "{values:?}");
                }
                let (listing, checked) = fixture.check_group(&groups[0], &nearest).unwrap();
                assert_eq!(listing.first_seen, Some(expected), "{flags:?}, {values:?}");
                assert_eq!(checked.level, level, "{flags:?}, {values:?}");
            }

            // Every value out of bounds: the listing fails as its median
            // would, and with none from the nearest it has no first_seen.
            let groups = merge_copies(copies_with_first_seen(&honest, &[pinned, pinned]));
            assert_eq!(
                fixture.check_group(&groups[0], &nearest),
                Err(PaymentError::Malformed(ListingError::TimeInFuture))
            );
            assert_eq!(
                fixture.check_group(&groups[0], &[8, 9]),
                Err(PaymentError::Malformed(ListingError::MissingFirstSeen))
            );
            if located {
                let groups = merge_copies(copies_with_first_seen(&honest, &[backdated]));
                let result = fixture.check_group(&groups[0], &nearest);
                if matches!(lookup, Lookup::Quote { .. }) {
                    // Searching only up to its latest payment time, a caller
                    // doesn't find the payment at all.
                    assert_eq!(result, Err(PaymentError::NotFound), "{flags:?}");
                } else {
                    assert_eq!(result, Err(PaymentError::FirstSeenTooEarly), "{flags:?}");
                }
            }
        }
    }

    #[test]
    fn a_minority_cannot_backdate_a_listing_nothing_locates() {
        // In the index, hiding all five: nothing bounds first_seen from
        // below, so only the median protects it.
        let nearest: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
        let needed = quorum_needed(nearest.len());
        for withheld in [false, true] {
            let fixture = fixture_flags(Flags {
                shown: ShownFields::NONE,
                in_index: true,
                withheld,
            });
            let honest = fixture.listing();
            let h = honest.first_seen.unwrap();
            for (values, expected) in [
                // Four of seven serve it, two of them colluding: a quorum,
                // but the colluders can't set the time.
                (vec![h, 0, h, 0], h),
                // Three colluders among six answering.
                (vec![0, h, 0, h, 0, h], h),
                // Three of seven colluding, all seven answering.
                (vec![0, 0, 0, h, h, h, h], h),
                // Colluders who are most of those answering decide.
                (vec![0, 0, 0, h], 0),
            ] {
                let groups = merge_copies(copies_with_first_seen(&honest, &values));
                assert_eq!(groups.len(), 1);
                assert!(groups[0].count_among(&nearest) >= needed);
                let (listing, checked) = fixture.check_group(&groups[0], &nearest).unwrap();
                assert_eq!(checked.level, CheckLevel::Reported);
                assert_eq!(listing.first_seen, Some(expected), "{values:?}");
            }
        }
    }

    #[test]
    fn check_levels_have_fixed_json_names() {
        assert_eq!(
            serde_json::to_string(&CheckLevel::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&CheckLevel::Reported).unwrap(),
            "\"reported\""
        );
        for level in [CheckLevel::Verified, CheckLevel::Reported] {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(serde_json::from_str::<CheckLevel>(&json).unwrap(), level);
        }
        assert!(serde_json::from_str::<CheckLevel>("\"Verified\"").is_err());
    }

    #[test]
    fn a_slow_node_clock_still_records_a_listing_that_checks_out() {
        let paid_at = block_time(BLOCK).unwrap();
        for flags in dated_by_first_seen() {
            let shown = flags.shown;
            let fixture = fixture_flags(flags);
            for hours_slow in [2, 5, 24] {
                let now = paid_at - hours_slow * 3_600 + 30;
                let listing = Listing::new(&fixture.envelope, &fixture.payment, now);
                assert_eq!(listing.first_seen, Some(first_seen_at(paid_at)));
                assert!(
                    fixture.verify(&listing).is_ok(),
                    "{shown:?}, {hours_slow} hours slow"
                );
            }
        }
    }

    #[test]
    fn version_1_envelopes_and_records_still_verify() {
        // Names only version 1 allows, and one both allow.
        for name in ["..", "a\u{200D}b", "invoice\u{202E}fdp.exe", "a\u{FF0F}b"] {
            let fixture = fixture_v1(name);
            let envelope = &fixture.envelope;
            assert_eq!(envelope.flags(), crate::Flags::V1);
            // Stored before version 2, it still reads; written today, a node
            // would refuse it as a new upload unless version 2 allows its name.
            assert_eq!(
                envelope.check_new_upload().is_ok(),
                name == "a\u{200D}b",
                "{name:?}"
            );

            // What a node records for it now, and what version 1 recorded.
            let listing = fixture.listing();
            assert_eq!(listing.validate(), Ok(()));
            let old = ListingV1 {
                address: envelope.address(),
                metadata: envelope.metadata().clone(),
                size: envelope.file_size(),
                payment: PaymentV1 {
                    tx_hash: fixture.payment.tx_hash,
                    block_number: fixture.payment.block_number,
                    block_timestamp: fixture.payment.block_timestamp,
                    log_index: fixture.payment.log_index,
                    quote: rmp_serde::to_vec(&with_nanos(
                        &decode_quote(&fixture.payment.quote).unwrap(),
                    ))
                    .unwrap(),
                },
            };
            let migrated = Listing::from(old);
            assert_eq!(migrated, listing, "{name:?}");
            let verified = Ok(ListingCheck {
                level: CheckLevel::Verified,
                paid_at: Some(PaidAt {
                    block_number: BLOCK,
                    log_index: LOG_INDEX,
                }),
            });
            assert_eq!(
                fixture.chain.check(&migrated, envelope, NOW),
                verified,
                "{name:?}"
            );
            // Served by a node, it pages, merges and checks out.
            assert_eq!(
                crate::check_list_page(
                    crate::ListingKey::MIN,
                    1,
                    std::slice::from_ref(&migrated),
                    true
                ),
                Ok(migrated.key().checked_next())
            );
            assert_eq!(
                crate::check_get_response(&envelope.address(), Some(migrated.clone())),
                Ok(Some(migrated.clone()))
            );
            let nearest = [1, 2, 3, 4, 5, 6, 7];
            let merged = crate::merge_copies(nearest.map(|peer| (peer, migrated.clone())));
            assert_eq!(merged.len(), 1);
            assert_eq!(merged[0].count_among(&nearest), 7);
            assert_eq!(merged[0].listing_among(&nearest), Some(migrated.clone()));

            // A tampered field is still caught.
            let mut tampered = migrated.clone();
            tampered.payment.block_number = Some(BLOCK + 1);
            assert_eq!(fixture.verify(&tampered), Err(PaymentError::WrongBlock));

            // And the uploader's proof of it checks out from the chain.
            let quote = decode_quote(&fixture.payment.quote).unwrap();
            let proof = EnvelopeProof::new(envelope, TX, &quote).unwrap();
            assert_eq!(proof.envelope, envelope.to_bytes());
            let proven =
                check_proof(&proof, &fixture.chain.receipts[0], BLOCK_TIME, &VAULT).unwrap();
            assert_eq!(proven.payment, fixture.payment);
            assert_eq!(proven.envelope.version(), crate::ENVELOPE_VERSION_1);
            assert_eq!(proven.data_map, envelope.data_map().cloned());
        }
    }

    #[test]
    fn quorums() {
        let expected = [1, 1, 2, 2, 3, 3, 4, 4, 4, 4];
        for (asked, needed) in expected.into_iter().enumerate() {
            assert_eq!(quorum_needed(asked), needed, "{asked} asked");
        }
        assert_eq!(
            quorum_needed(ant_protocol::CLOSE_GROUP_SIZE),
            QUORUM_THRESHOLD
        );
        assert_eq!(quorum_needed(usize::MAX), QUORUM_THRESHOLD);
    }
}
