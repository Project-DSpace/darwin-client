//! Root payments: the tree a root vault records each wave of payments under.
//!
//! A root vault takes a list of storage payments in one call: a *wave*. Each
//! payment pays a quote's amount to the payee the quote names, as the
//! per-quote vault's payments do, but the vault keeps one record for the
//! whole wave instead of one per paid quote, under the wave's *key*. A wave
//! holds 1 to [`LEAF_LIMIT`] payments, in strictly ascending quote-hash
//! order, each with an amount above zero and a payee other than the zero
//! address ([`Wave::new`]).
//!
//! The key comes from a tree of the wave's payments:
//!
//! - leaf = keccak256(0x00 ‖ quote hash ‖ payee ‖ amount) ([`leaf`]);
//! - pair = keccak256(0x01 ‖ left ‖ right) ([`pair`]);
//! - each level pairs its nodes in order, and an unpaired last node is
//!   carried up to the next level unchanged; the last node left is the root,
//!   so a wave of one payment has its leaf as its root ([`Wave::root`]);
//! - key = keccak256(0x02 ‖ vault address ‖ root ‖ leaf count) ([`key`]).
//!
//! Numbers are 32-byte big-endian words, and addresses their 20 bytes.
//!
//! A payment's *path* holds its siblings from the leaf up, one for each level
//! where it has one, and nothing more: at most [`MAX_PATH_LEN`] hashes
//! ([`Wave::path`]). With the payment, its place in the wave and the wave's
//! leaf count, the path gives the key the wave is recorded under
//! ([`leaf_key`]): the check a storer makes before it reads the vault's
//! record under that key.
//!
//! Each wave a root vault records logs, in this order: one `DataPaymentMade`
//! for each payment, as the per-quote vault logs a paid quote
//! ([`DATA_PAYMENT_MADE_TOPIC`]); one `RootPaid` naming the wave's key, its
//! payer, its leaf count and its total ([`ROOT_PAID_TOPIC`]); then one token
//! `Transfer` from the payer to each distinct payee, of the sum of its
//! payments, in the order the payees first appear ([`TRANSFER_TOPIC`],
//! [`Wave::sums`]). A wave sent again, under a key already recorded, moves
//! nothing and logs nothing. [`recorded_wave`] reads a wave back from the
//! receipt of the transaction that recorded it.
//!
//! The vault's own test vectors are kept in `src/root/vectors/`, and every
//! function here is checked against them.

use crate::payment::{PaymentLog, PaymentReceipt, RootVault, DATA_PAYMENT_MADE_TOPIC};
use ant_protocol::evm::Amount;
use sha3::{Digest, Keccak256};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// The most payments a wave holds: a root vault's leaf limit.
pub const LEAF_LIMIT: u64 = 512;

/// The most hashes a path holds: one for each level above the leaves of a
/// wave of [`LEAF_LIMIT`] payments.
pub const MAX_PATH_LEN: usize = 9;

/// `keccak256("RootPaid(bytes32,address,uint256,uint256)")`: the event a
/// root vault logs once for each wave it records, after the wave's
/// `DataPaymentMade` logs. The key is its one indexed field, topic 1; its data
/// is the payer, the leaf count and the total, one 32-byte word each.
pub const ROOT_PAID_TOPIC: [u8; 32] = [
    0x59, 0xbc, 0x12, 0xd0, 0x04, 0x00, 0x84, 0x1d, 0x77, 0xb5, 0x41, 0x52, 0x62, 0xa9, 0xf9, 0x2a,
    0x97, 0x64, 0xd9, 0x90, 0x7e, 0x0a, 0xd0, 0xbb, 0xf0, 0x0b, 0xbd, 0xe3, 0x4c, 0x02, 0xd1, 0x9a,
];

/// `keccak256("Transfer(address,address,uint256)")`: a token's transfer
/// event. The sender and the receiver are topics 1 and 2, and the amount is
/// its data.
pub const TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// Keccak-256, as Ethereum computes it, over `parts` joined.
fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `n` as a 32-byte big-endian word.
fn word(n: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&n.to_be_bytes());
    word
}

/// A payment's leaf: keccak256(0x00 ‖ quote hash ‖ payee ‖ amount).
#[must_use]
pub fn leaf(quote_hash: &[u8; 32], payee: &[u8; 20], amount: &Amount) -> [u8; 32] {
    keccak256(&[&[0x00], quote_hash, payee, &amount.to_be_bytes::<32>()])
}

/// The node above two others: keccak256(0x01 ‖ left ‖ right).
#[must_use]
pub fn pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    keccak256(&[&[0x01], left, right])
}

/// The key a wave of `leaf_count` payments whose tree has root `root` is
/// recorded under at `vault`: keccak256(0x02 ‖ vault ‖ root ‖ leaf count).
#[must_use]
pub fn key(vault: &[u8; 20], root: &[u8; 32], leaf_count: u64) -> [u8; 32] {
    keccak256(&[&[0x02], vault, root, &word(leaf_count)])
}

/// The root a payment's path leads to, from its leaf, its place `index` in a
/// wave of `leaf_count` payments, and `path`: the leaf is hashed up the tree
/// with each sibling in turn, the place and the leaf count telling left from
/// right and which levels carry the node up unpaired. This is how a root
/// vault checks a payment against its records, up to the read of its record
/// under the root's [`key`].
///
/// `None`, before any hashing, for a leaf count of 0 or above [`LEAF_LIMIT`]
/// or a place outside the wave; and `None` for a path with fewer or more
/// hashes than the place has siblings.
#[must_use]
pub fn root_from_path(
    leaf: &[u8; 32],
    index: u64,
    leaf_count: u64,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if leaf_count == 0 || leaf_count > LEAF_LIMIT || index >= leaf_count {
        return None;
    }
    let mut siblings = path.iter();
    let mut node = *leaf;
    let mut index = index;
    let mut width = leaf_count;
    while width > 1 {
        if index % 2 == 1 {
            node = pair(siblings.next()?, &node);
        } else if index + 1 < width {
            node = pair(&node, siblings.next()?);
        }
        index /= 2;
        width = width.div_ceil(2);
    }
    siblings.next().is_none().then_some(node)
}

/// The key the wave holding `payment` is recorded under at `vault`, from the
/// payment's place `index` in a wave of `leaf_count` payments and its path:
/// [`root_from_path`] from the payment's leaf, then [`key`]. A storer reads
/// the vault's record under this key. `None` where [`root_from_path`] gives
/// none, so nothing is read.
#[must_use]
pub fn leaf_key(
    vault: &[u8; 20],
    payment: &RootPayment,
    index: u64,
    leaf_count: u64,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    root_from_path(&payment.leaf(), index, leaf_count, path)
        .map(|root| key(vault, &root, leaf_count))
}

/// One payment of a wave, as a root vault takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootPayment {
    /// The paid quote's hash.
    pub quote_hash: [u8; 32],
    /// The payee: the rewards address the quote names.
    pub payee: [u8; 20],
    /// The amount paid.
    pub amount: Amount,
}

impl RootPayment {
    /// The payment's [`leaf`].
    #[must_use]
    pub fn leaf(&self) -> [u8; 32] {
        leaf(&self.quote_hash, &self.payee, &self.amount)
    }
}

/// Why a root vault refuses a wave. Each refusal but the first names the
/// place of the first payment that fails, as the vault's own errors do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WaveError {
    /// The wave holds no payments, or more than [`LEAF_LIMIT`].
    #[error("a wave holds 1 to {limit} payments, not {count}", limit = LEAF_LIMIT, count = .0)]
    LeafCountOutOfRange(usize),
    /// A payment's quote hash is zero.
    #[error("payment {0} has a zero quote hash")]
    ZeroQuoteHash(usize),
    /// A payment's quote hash is the one before it.
    #[error("payment {0} repeats the quote hash before it")]
    RepeatedQuoteHash(usize),
    /// A payment's quote hash is below the one before it.
    #[error("payment {0} has a quote hash below the one before it")]
    QuoteHashesNotAscending(usize),
    /// A payment's amount is zero.
    #[error("payment {0} has a zero amount")]
    ZeroAmount(usize),
    /// A payment's payee is the zero address.
    #[error("payment {0} has the zero address as its payee")]
    ZeroPayee(usize),
    /// The amounts add up past 2^256 - 1, at this payment.
    #[error("the amounts add up past 2^256 - 1 at payment {0}")]
    TotalOverflow(usize),
}

/// A wave a root vault takes, with its tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wave {
    payments: Vec<RootPayment>,
    /// The tree's levels: the leaves first, the root alone last.
    levels: Vec<Vec<[u8; 32]>>,
    total: Amount,
}

impl Wave {
    /// The wave of `payments`, in the order given, checked as a root vault
    /// checks a wave before it pays it: 1 to [`LEAF_LIMIT`] payments; then,
    /// payment by payment, a quote hash above the one before it (the first
    /// above zero), an amount above zero, a payee other than the zero address,
    /// and a total that fits in 256 bits. So a wave refused here is refused by
    /// the vault, at the same payment and for the same reason.
    ///
    /// # Errors
    ///
    /// Returns the first check that fails.
    pub fn new(payments: Vec<RootPayment>) -> Result<Self, WaveError> {
        let count = payments.len();
        if !(1..=LEAF_LIMIT).contains(&(count as u64)) {
            return Err(WaveError::LeafCountOutOfRange(count));
        }
        let mut previous = [0; 32];
        let mut total = Amount::ZERO;
        for (index, payment) in payments.iter().enumerate() {
            if payment.quote_hash <= previous {
                return Err(if payment.quote_hash == [0; 32] {
                    WaveError::ZeroQuoteHash(index)
                } else if payment.quote_hash == previous {
                    WaveError::RepeatedQuoteHash(index)
                } else {
                    WaveError::QuoteHashesNotAscending(index)
                });
            }
            if payment.amount.is_zero() {
                return Err(WaveError::ZeroAmount(index));
            }
            if payment.payee == [0; 20] {
                return Err(WaveError::ZeroPayee(index));
            }
            total = total
                .checked_add(payment.amount)
                .ok_or(WaveError::TotalOverflow(index))?;
            previous = payment.quote_hash;
        }
        let mut levels = vec![payments.iter().map(RootPayment::leaf).collect::<Vec<_>>()];
        while let Some(below) = levels.last().filter(|level| level.len() > 1) {
            let above = below
                .chunks(2)
                .map(|nodes| match nodes {
                    [left, right] => pair(left, right),
                    [carried] => *carried,
                    _ => unreachable!("chunks of one or two"),
                })
                .collect();
            levels.push(above);
        }
        Ok(Self {
            payments,
            levels,
            total,
        })
    }

    /// The payments, in the wave's order.
    #[must_use]
    pub fn payments(&self) -> &[RootPayment] {
        &self.payments
    }

    /// How many payments the wave holds: its leaf count.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        // At most LEAF_LIMIT, so it fits.
        self.payments.len() as u64
    }

    /// The tree's root.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or_default()
    }

    /// The [`key`] the wave is recorded under at `vault`.
    #[must_use]
    pub fn key(&self, vault: &[u8; 20]) -> [u8; 32] {
        key(vault, &self.root(), self.leaf_count())
    }

    /// The sum of the amounts: what the wave pays in all.
    #[must_use]
    pub fn total(&self) -> Amount {
        self.total
    }

    /// The path of the payment at place `index`: its siblings from the leaf
    /// up, one for each level where it has one. `None` for a place outside
    /// the wave.
    #[must_use]
    pub fn path(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.payments.len() {
            return None;
        }
        let (_, below_root) = self.levels.split_last()?;
        let mut index = index;
        let mut path = Vec::with_capacity(below_root.len());
        for level in below_root {
            if let Some(sibling) = level.get(index ^ 1) {
                path.push(*sibling);
            }
            index /= 2;
        }
        Some(path)
    }

    /// Each distinct payee with the sum of its payments, in the order the
    /// payees first appear: the token transfers a root vault makes for the
    /// wave, in the order it makes them.
    #[must_use]
    pub fn sums(&self) -> Vec<([u8; 20], Amount)> {
        let mut sums: Vec<([u8; 20], Amount)> = Vec::new();
        let mut places: HashMap<[u8; 20], usize> = HashMap::new();
        for payment in &self.payments {
            match places.entry(payment.payee) {
                // No sum can pass the total, which fits.
                Entry::Occupied(place) => {
                    let sum = &mut sums[*place.get()].1;
                    *sum = sum.saturating_add(payment.amount);
                }
                Entry::Vacant(place) => {
                    place.insert(sums.len());
                    sums.push((payment.payee, payment.amount));
                }
            }
        }
        sums
    }
}

/// A wave a root vault recorded, as the receipt of the transaction that
/// recorded it shows it ([`recorded_wave`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedWave {
    /// The wave: its payments, in order, and its tree.
    pub wave: Wave,
    /// The key the wave is recorded under, which its `RootPaid` log names.
    pub key: [u8; 32],
    /// The payer its `RootPaid` log names: the account that sent the wave,
    /// from which every transfer comes.
    pub payer: [u8; 20],
    /// The log index of the wave's first `DataPaymentMade` log. Payment `i`'s
    /// log is at `first_log_index + i`, and `RootPaid` follows the last.
    pub first_log_index: u64,
}

/// Why a receipt doesn't show a wave whole, as a root vault logs a wave it
/// records ([`recorded_wave`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WaveLogError {
    /// The vault's `DataPaymentMade` logs from the given one on don't run on
    /// to a `RootPaid` log of the vault.
    #[error("no RootPaid log follows the payment's log")]
    NoRootPaid,
    /// The `RootPaid` log is not as the vault writes it: the key as its one
    /// indexed field, and three words of data, an address for the payer, a
    /// leaf count from 1 to [`LEAF_LIMIT`] and the total.
    #[error("the RootPaid log is malformed")]
    BadRootPaid,
    /// The leaf count's logs right before `RootPaid` are not all the vault's
    /// `DataPaymentMade` logs with an address for a payee, or don't hold the
    /// given log.
    #[error("the wave's payment logs don't all come right before its RootPaid log")]
    Payments,
    /// The logged payments are not a wave the vault takes.
    #[error("the logged payments are not a wave: {0}")]
    Refused(WaveError),
    /// `RootPaid`'s key or total is not the logged wave's.
    #[error("RootPaid's key or total is not the logged wave's")]
    NotTheWave,
    /// After `RootPaid`, the token's next transfers are not one from the
    /// payer to each of the wave's payees, of the sum of its payments.
    #[error(
        "the token transfers after RootPaid are not one from the payer to each payee, \
         of the sum of its payments"
    )]
    Transfers,
}

/// The wave holding `vault`'s `DataPaymentMade` log at `log_index` in
/// `receipt`, read back as the vault logs a wave it records:
///
/// 1. that log and the vault's `DataPaymentMade` logs after it run on to the
///    vault's `RootPaid` log, and the leaf count it names of logs right
///    before it are the wave's payments, that log among them;
/// 2. those payments are a wave the vault takes ([`Wave::new`]), whose key
///    and total `RootPaid` names;
/// 3. after `RootPaid`, the token's next transfers, with nothing between them
///    but the token's own other logs, are one from `RootPaid`'s payer to each
///    of the wave's payees, of the sum of its payments ([`Wave::sums`]), in
///    any order.
///
/// Logs are found by their log index, which counts on without a gap through
/// a transaction's logs. An index two of the receipt's logs share holds
/// neither. Whether the transaction succeeded is the caller's to check.
///
/// # Errors
///
/// Returns the first of these checks that fails.
pub fn recorded_wave(
    receipt: &PaymentReceipt,
    vault: &RootVault,
    log_index: u64,
) -> Result<RecordedWave, WaveLogError> {
    let mut waves = RecordedWaves::new(receipt, *vault);
    let place = waves.place(log_index)?;
    let wave = waves.whole(&place)?;
    Ok(RecordedWave {
        wave,
        key: place.key,
        payer: place.payer,
        first_log_index: place.first,
    })
}

/// A receipt's waves at one root vault, read as [`recorded_wave`] reads
/// one, for any number of the vault's logs ([`RecordedWaves::check`]): each
/// wave is checked as a whole once, however many of its payments' logs are
/// asked about, so checking each of a wave's logs costs about as much as
/// checking one.
pub(crate) struct RecordedWaves<'r> {
    logs: Logs<'r>,
    vault: RootVault,
    /// The last walk from a payment's log on to a `RootPaid` log: the log it
    /// started from, and the `RootPaid` log's index.
    walked: Option<(u64, u64)>,
    /// Whether each wave checked as a whole so far checks out, by its
    /// `RootPaid` log's index.
    checked: BTreeMap<u64, Result<(), WaveLogError>>,
}

/// Where the wave holding a payment's log sits in a receipt, and what its
/// `RootPaid` log names.
struct WavePlace {
    /// The `RootPaid` log's index.
    root_paid: u64,
    /// The index of the wave's first `DataPaymentMade` log.
    first: u64,
    /// The key `RootPaid` names.
    key: [u8; 32],
    /// The payer `RootPaid` names.
    payer: [u8; 20],
    /// The total `RootPaid` names.
    total: Amount,
}

#[cfg(test)]
thread_local! {
    /// How many waves this thread has checked as a whole: the tests count
    /// the work a receipt costs with it.
    pub(crate) static WHOLE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl<'r> RecordedWaves<'r> {
    pub(crate) fn new(receipt: &'r PaymentReceipt, vault: RootVault) -> Self {
        Self {
            logs: Logs::new(receipt),
            vault,
            walked: None,
            checked: BTreeMap::new(),
        }
    }

    /// Whether the receipt shows whole the wave holding the vault's
    /// `DataPaymentMade` log at `log_index`: [`recorded_wave`]'s checks, the
    /// same answer. The checks that depend on the log alone run for each
    /// log, and those of the wave as a whole (its payments, its key and
    /// total, its transfers) once for all its logs, so a wave that fails
    /// them fails for each of its logs from that one check.
    ///
    /// # Errors
    ///
    /// The first of [`recorded_wave`]'s checks that fails.
    pub(crate) fn check(&mut self, log_index: u64) -> Result<(), WaveLogError> {
        let place = self.place(log_index)?;
        if let Some(checked) = self.checked.get(&place.root_paid) {
            return *checked;
        }
        let checked = self.whole(&place).map(drop);
        self.checked.insert(place.root_paid, checked);
        checked
    }

    /// The vault's log at `log_index`, if the receipt holds it alone there.
    fn vault_log(&self, log_index: u64) -> Option<&'r PaymentLog> {
        self.logs
            .at(log_index)
            .filter(|log| log.address == self.vault.address)
    }

    /// [`recorded_wave`]'s first check for the vault's log at `log_index`:
    /// the logs from it on run on to the vault's `RootPaid` log, which is as
    /// the vault writes it and counts back to a first payment no later than
    /// this one. No hashing, and a run of payment logs is walked once
    /// however many of its logs are asked about in order.
    fn place(&mut self, log_index: u64) -> Result<WavePlace, WaveLogError> {
        let root_paid = match self.walked {
            // The last walk passed this log, and found each log it passed to
            // be one of the vault's payment logs: this one's walk would end
            // at the same RootPaid log.
            Some((from, root_paid)) if from < log_index && log_index < root_paid => root_paid,
            _ => {
                let root_paid = self.walk(log_index)?;
                self.walked = Some((log_index, root_paid));
                root_paid
            }
        };
        let (key, payer, leaf_count, total) = self
            .vault_log(root_paid)
            .and_then(root_paid_fields)
            .ok_or(WaveLogError::BadRootPaid)?;
        let first = root_paid
            .checked_sub(leaf_count)
            .filter(|first| *first <= log_index)
            .ok_or(WaveLogError::Payments)?;
        Ok(WavePlace {
            root_paid,
            first,
            key,
            payer,
            total,
        })
    }

    /// The index of the vault's `RootPaid` log that the vault's
    /// `DataPaymentMade` logs from the one at `log_index` on run on to.
    fn walk(&self, log_index: u64) -> Result<u64, WaveLogError> {
        if !self.vault_log(log_index).is_some_and(is_payment_log) {
            return Err(WaveLogError::Payments);
        }
        let mut at = log_index;
        loop {
            at = at.checked_add(1).ok_or(WaveLogError::NoRootPaid)?;
            match self.vault_log(at) {
                Some(log) if is_payment_log(log) => {}
                Some(log) if log.topics.first() == Some(&ROOT_PAID_TOPIC) => return Ok(at),
                _ => return Err(WaveLogError::NoRootPaid),
            }
        }
    }

    /// The rest of [`recorded_wave`]'s checks, of the wave at `place` as a
    /// whole: the leaf count's logs before `RootPaid` are all the vault's
    /// payment logs, their payments are a wave the vault takes, whose key
    /// and total `RootPaid` names, and the token's transfers after `RootPaid`
    /// pay each payee its sum. They depend on the `RootPaid` log alone, not
    /// on which of the wave's logs is asked about.
    fn whole(&self, place: &WavePlace) -> Result<Wave, WaveLogError> {
        #[cfg(test)]
        WHOLE_CHECKS.with(|checks| checks.set(checks.get() + 1));
        let payments = (place.first..place.root_paid)
            .map(|index| {
                self.vault_log(index)
                    .filter(|log| is_payment_log(log))
                    .and_then(payment_in)
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(WaveLogError::Payments)?;
        let wave = Wave::new(payments).map_err(WaveLogError::Refused)?;
        if wave.key(&self.vault.address) != place.key || wave.total() != place.total {
            return Err(WaveLogError::NotTheWave);
        }
        check_transfers(
            &self.logs,
            &self.vault,
            place.root_paid,
            &place.payer,
            wave.sums(),
        )?;
        Ok(wave)
    }
}

/// A receipt's logs by log index. An index two logs share holds neither: one
/// transaction never logs twice at one place.
struct Logs<'r>(BTreeMap<u64, Option<&'r PaymentLog>>);

impl<'r> Logs<'r> {
    fn new(receipt: &'r PaymentReceipt) -> Self {
        let mut logs = BTreeMap::new();
        for log in &receipt.logs {
            logs.entry(log.log_index)
                .and_modify(|shared| *shared = None)
                .or_insert(Some(log));
        }
        Self(logs)
    }

    fn at(&self, log_index: u64) -> Option<&'r PaymentLog> {
        self.0.get(&log_index).copied().flatten()
    }
}

/// Whether `log` is shaped as a `DataPaymentMade` log: its signature and
/// three indexed fields.
fn is_payment_log(log: &PaymentLog) -> bool {
    log.topics.len() == 4 && log.topics[0] == DATA_PAYMENT_MADE_TOPIC
}

/// The address in a 32-byte word, if its first 12 bytes are zero.
fn address_in(word: &[u8; 32]) -> Option<[u8; 20]> {
    let (zeros, address) = word.split_at(12);
    if zeros.iter().any(|&byte| byte != 0) {
        return None;
    }
    address.try_into().ok()
}

/// The payment a `DataPaymentMade` log records.
fn payment_in(log: &PaymentLog) -> Option<RootPayment> {
    let [_, payee, amount, quote_hash] = log.topics.as_slice() else {
        return None;
    };
    Some(RootPayment {
        quote_hash: *quote_hash,
        payee: address_in(payee)?,
        amount: Amount::from_be_bytes(*amount),
    })
}

/// A `RootPaid` log's key, payer, leaf count and total, if it is as the vault
/// writes it.
fn root_paid_fields(log: &PaymentLog) -> Option<([u8; 32], [u8; 20], u64, Amount)> {
    let [topic, key] = log.topics.as_slice() else {
        return None;
    };
    if *topic != ROOT_PAID_TOPIC || log.data.len() != 96 {
        return None;
    }
    let word = |at: usize| -> Option<[u8; 32]> { log.data.get(at..at + 32)?.try_into().ok() };
    let payer = address_in(&word(0)?)?;
    let leaf_count = u64::try_from(Amount::from_be_bytes(word(32)?))
        .ok()
        .filter(|count| (1..=LEAF_LIMIT).contains(count))?;
    let total = Amount::from_be_bytes(word(64)?);
    Some((*key, payer, leaf_count, total))
}

/// A token `Transfer` log's sender, receiver and amount.
fn transfer_in(log: &PaymentLog) -> Option<([u8; 20], [u8; 20], Amount)> {
    let [_, from, to] = log.topics.as_slice() else {
        return None;
    };
    let amount: [u8; 32] = log.data.as_slice().try_into().ok()?;
    Some((
        address_in(from)?,
        address_in(to)?,
        Amount::from_be_bytes(amount),
    ))
}

/// The token's transfers after the `RootPaid` log at `root_paid`: one from
/// `payer` to each payee in `sums`, of its sum, with nothing between them but
/// the token's own other logs.
fn check_transfers(
    logs: &Logs<'_>,
    vault: &RootVault,
    root_paid: u64,
    payer: &[u8; 20],
    sums: Vec<([u8; 20], Amount)>,
) -> Result<(), WaveLogError> {
    let mut owed: HashMap<[u8; 20], Amount> = sums.into_iter().collect();
    let mut at = root_paid;
    while !owed.is_empty() {
        at = at.checked_add(1).ok_or(WaveLogError::Transfers)?;
        let log = logs
            .at(at)
            .filter(|log| log.address == vault.token)
            .ok_or(WaveLogError::Transfers)?;
        if log.topics.first() != Some(&TRANSFER_TOPIC) {
            continue;
        }
        let (from, to, amount) = transfer_in(log).ok_or(WaveLogError::Transfers)?;
        if from != *payer || owed.remove(&to) != Some(amount) {
            return Err(WaveLogError::Transfers);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
