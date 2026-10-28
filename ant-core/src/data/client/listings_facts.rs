//! What a [`ListingChain`](super::listings::ListingChain) with a store
//! ([`ListingChain::with_store`](super::listings::ListingChain::with_store))
//! keeps of what it reads: envelopes, and the payment vault's chain facts.
//!
//! - **Envelopes**, by address, for good: an envelope is content-addressed,
//!   so its bytes are checked against its address whenever they are read.
//! - **Chain facts**, kept per vault, which is all a listing's check reads
//!   from the chain:
//!   - a transaction's receipt, as little of it as a check reads: whether it
//!     succeeded, its block, and the logs in it of the vaults read and of the
//!     root vault's token, each with its own address and data. A reader with
//!     a root vault keeps its receipts and quotes' payments apart from a
//!     reader of the per-quote vault alone, whose receipts hold fewer logs;
//!   - a block's timestamp;
//!   - a quote's payments, as log queries found them. The per-quote vault
//!     records a quote's payment once and skips any repeat, but a root vault
//!     can record a quote again in a later wave, so a reader with a root
//!     vault takes the kept payments as what was found so far, not as all a
//!     quote will have: where none of them is the payment a listing shows,
//!     it searches again and keeps what it finds beside them;
//!   - the transaction of the vault's log at a block and log index.
//!
//! A fact is used as soon as it is read. It is kept for good only once its
//! block is at or below the block the RPC reports as finalized, and a
//! second provider has returned the same; until then it is held in memory
//! while its block is above the finalized one, and dropped otherwise. "Not
//! found", errors and block times later than the clock are never kept, and
//! nor is anything a check decides from the facts.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ant_listings::{Envelope, PaymentLog, PaymentReceipt, VaultSet};
use ant_protocol::{compute_address, XorName};
use heed::types::Bytes;
use heed::Database;
use tokio::time::Instant;
use tracing::debug;

use super::listings_store::ListingsStore;
use crate::data::error::Result;

/// The database holding envelopes, by address.
pub(crate) const ENVELOPES_DB: &str = "facts_envelopes";

/// The database holding receipts, by vault and transaction.
pub(crate) const RECEIPTS_DB: &str = "facts_receipts";

/// The database holding block timestamps, by vault and block.
pub(crate) const BLOCKS_DB: &str = "facts_blocks";

/// The database holding quotes' payments, by vault and quote hash.
pub(crate) const QUOTES_DB: &str = "facts_quotes";

/// The database holding the transactions of vault logs, by vault, block and
/// log index.
pub(crate) const BLOCK_LOGS_DB: &str = "facts_block_logs";

/// While facts wait above the finalized block last read, it is read again
/// at most this often: once a minute, the producer's cycle.
pub(crate) const FINALIZED_REFRESH: Duration = Duration::from_secs(60);

/// The version of the encoding of every chain fact kept, its first byte.
const FORMAT: u8 = 1;

/// The length of a receipt's or a quote's key kept by a reader of the
/// per-quote vault alone ([`Facts::key`]): the vault (20 bytes) and the
/// transaction or quote hash (32). A reader with a root vault keys them
/// longer, its address and token after the vault ([`Facts::logs_key`]).
const UNROOTED_KEY_LEN: usize = 20 + 32;

/// The version of the encoding of a receipt kept, its first byte: each log
/// with its own address and data ([`encode_receipt`]). Receipts of
/// [`FORMAT`] held the per-quote vault's logs alone, with no address or
/// data; they are read only by a reader of the per-quote vault alone.
const RECEIPT_FORMAT: u8 = 2;

/// Whether a receipt read with `vaults` keeps the log of `address`: the
/// vaults' logs, and the root vault's token's, whose transfers show what a
/// wave paid ([`ant_listings::recorded_wave`]).
pub(crate) fn receipt_keeps(vaults: &VaultSet, address: &[u8; 20]) -> bool {
    vaults.contains(address) || vaults.root.is_some_and(|root| root.token == *address)
}

/// A vault `DataPaymentMade` log, located: a payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct VaultLog {
    pub(crate) tx_hash: [u8; 32],
    pub(crate) block_number: u64,
    pub(crate) log_index: u64,
}

/// A fact as a lookup has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Known<T> {
    pub(crate) value: T,
    /// Kept for good.
    pub(crate) kept: bool,
    /// The provider it was read through (an index), where it isn't kept.
    pub(crate) source: Option<usize>,
}

impl<T> Known<T> {
    /// Read just now through provider `source`.
    pub(crate) fn read(value: T, source: usize) -> Self {
        Self {
            value,
            kept: false,
            source: Some(source),
        }
    }
}

/// Facts kept for good in one write.
#[derive(Debug, Default)]
pub(crate) struct Keep {
    pub(crate) receipts: Vec<PaymentReceipt>,
    pub(crate) blocks: Vec<(u64, u64)>,
    pub(crate) quotes: Vec<([u8; 32], Vec<VaultLog>)>,
    pub(crate) block_logs: Vec<((u64, u64), [u8; 32])>,
}

impl Keep {
    pub(crate) fn is_empty(&self) -> bool {
        self.receipts.is_empty()
            && self.blocks.is_empty()
            && self.quotes.is_empty()
            && self.block_logs.is_empty()
    }
}

/// Facts read but not kept yet, with the provider each came through.
#[derive(Debug, Default)]
struct Held {
    receipts: HashMap<[u8; 32], (PaymentReceipt, usize)>,
    blocks: HashMap<u64, (u64, usize)>,
    quotes: HashMap<[u8; 32], Vec<VaultLog>>,
    block_logs: HashMap<(u64, u64), [u8; 32]>,
}

/// The finalized block, as last read, and when it was last asked for.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Finalized {
    pub(crate) block: Option<u64>,
    pub(crate) asked_at: Option<Instant>,
}

/// The envelopes and chain facts a reader keeps. See the module docs.
pub(crate) struct Facts {
    vaults: VaultSet,
    store: ListingsStore,
    envelopes: Database<Bytes, Bytes>,
    receipts: Database<Bytes, Bytes>,
    blocks: Database<Bytes, Bytes>,
    quotes: Database<Bytes, Bytes>,
    block_logs: Database<Bytes, Bytes>,
    held: Mutex<Held>,
    /// Locked while the finalized block is read, so it is read once for
    /// every lookup waiting on it.
    pub(crate) finalized: tokio::sync::Mutex<Finalized>,
}

impl std::fmt::Debug for Facts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Facts")
            .field("vault", &hex::encode(self.vaults.v2))
            .finish_non_exhaustive()
    }
}

impl Facts {
    /// The facts about `vaults` kept in `store`, its databases created if
    /// they don't exist.
    ///
    /// # Errors
    ///
    /// If the databases can't be opened.
    pub(crate) fn open(store: &ListingsStore, vaults: VaultSet) -> Result<Self> {
        let facts = Self {
            vaults,
            store: store.clone(),
            envelopes: store.database(ENVELOPES_DB)?,
            receipts: store.database(RECEIPTS_DB)?,
            blocks: store.database(BLOCKS_DB)?,
            quotes: store.database(QUOTES_DB)?,
            block_logs: store.database(BLOCK_LOGS_DB)?,
            held: Mutex::default(),
            finalized: tokio::sync::Mutex::default(),
        };
        facts.drop_unrooted();
        Ok(facts)
    }

    /// Read `vaults` from now on: the receipts and quotes' payments held of
    /// the vaults read before are dropped, and those kept for them are no
    /// longer read.
    pub(crate) fn set_vaults(&mut self, vaults: VaultSet) {
        if vaults != self.vaults {
            self.vaults = vaults;
            {
                let mut held = self.held();
                held.receipts.clear();
                held.quotes.clear();
            }
            self.drop_unrooted();
        }
    }

    /// For a reader with a root vault, drop the receipts and quotes'
    /// payments kept for its per-quote vault alone ([`Self::key`] rather
    /// than [`Self::logs_key`]), as a reader of that vault kept them before
    /// it read a root vault. It never reads them ([`Self::logs_key`]), and
    /// they can't be carried over: a receipt kept so lacks its logs' data
    /// and the root vault's logs, and a quote's payments lack the root
    /// vault's. The facts are read again as listings need them. Blocks and
    /// block logs are keyed under the per-quote vault alone for every
    /// reader, and stay. A failure is logged: the entries are left, unread.
    fn drop_unrooted(&self) {
        if self.vaults.root.is_none() {
            return;
        }
        let drop = || -> heed::Result<usize> {
            let mut txn = self.store.env().write_txn()?;
            let mut dropped = 0;
            for database in [&self.receipts, &self.quotes] {
                let unrooted = database
                    .prefix_iter(&txn, &self.vaults.v2[..])?
                    .filter_map(|entry| {
                        entry
                            .map(|(key, _)| (key.len() == UNROOTED_KEY_LEN).then(|| key.to_vec()))
                            .transpose()
                    })
                    .collect::<heed::Result<Vec<_>>>()?;
                for key in &unrooted {
                    database.delete(&mut txn, key)?;
                }
                dropped += unrooted.len();
            }
            txn.commit()?;
            Ok(dropped)
        };
        match drop() {
            Ok(0) => {}
            Ok(dropped) => debug!(
                "Dropped {dropped} receipt(s) and quote payment(s) kept for the per-quote vault \
                 alone; they are read again with the root vault's logs"
            ),
            Err(e) => debug!("Could not drop the facts kept for the per-quote vault alone: {e}"),
        }
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        // Plain maps, whole after any panic.
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The bytes kept in `database` at `key`. A store that can't be read
    /// is logged and taken as holding nothing: the fact is read again.
    fn get(&self, database: &Database<Bytes, Bytes>, key: &[u8]) -> Option<Vec<u8>> {
        let read = || -> heed::Result<Option<Vec<u8>>> {
            let txn = self.store.env().read_txn()?;
            Ok(database.get(&txn, key)?.map(<[u8]>::to_vec))
        };
        read().unwrap_or_else(|e| {
            debug!("Could not read the listings store: {e}");
            None
        })
    }

    /// The envelope kept for `address`, if any. Bytes that don't hash to
    /// `address`, or don't decode, are not returned.
    pub(crate) fn envelope(&self, address: &XorName) -> Option<Envelope> {
        let bytes = self.get(&self.envelopes, address)?;
        if compute_address(&bytes) != *address {
            debug!(
                "The envelope kept for {} doesn't hash to its address",
                hex::encode(address)
            );
            return None;
        }
        Envelope::from_bytes(&bytes)
            .map_err(|e| {
                debug!(
                    "The envelope kept for {} doesn't decode: {e}",
                    hex::encode(address)
                );
            })
            .ok()
    }

    /// Keep `chunk`, the envelope chunk fetched for `address`, for good, if
    /// it hashes to `address`. A failure is logged: the envelope is fetched
    /// again when next needed.
    pub(crate) fn keep_envelope(&self, address: &XorName, chunk: &[u8]) {
        if compute_address(chunk) != *address {
            debug!(
                "Not keeping an envelope for {}: it doesn't hash to its address",
                hex::encode(address)
            );
            return;
        }
        let write = || -> heed::Result<()> {
            let mut txn = self.store.env().write_txn()?;
            self.envelopes.put(&mut txn, address, chunk)?;
            txn.commit()
        };
        if let Err(e) = write() {
            debug!(
                "Could not keep the envelope for {}: {e}",
                hex::encode(address)
            );
        }
    }

    /// The receipt of `tx_hash`, kept or held.
    pub(crate) fn receipt(&self, tx_hash: &[u8; 32]) -> Option<Known<PaymentReceipt>> {
        if let Some(receipt) = self.kept_receipt(tx_hash) {
            return Some(Known {
                value: receipt,
                kept: true,
                source: None,
            });
        }
        self.held()
            .receipts
            .get(tx_hash)
            .map(|(receipt, source)| Known::read(receipt.clone(), *source))
    }

    /// The receipt of `tx_hash`, if kept for good.
    pub(crate) fn kept_receipt(&self, tx_hash: &[u8; 32]) -> Option<PaymentReceipt> {
        let bytes = self.get(&self.receipts, &self.logs_key(tx_hash))?;
        decode_receipt(*tx_hash, &self.vaults, &bytes)
    }

    /// The timestamp of block `number`, kept or held.
    pub(crate) fn block(&self, number: u64) -> Option<Known<u64>> {
        if let Some(timestamp) = self.kept_block(number) {
            return Some(Known {
                value: timestamp,
                kept: true,
                source: None,
            });
        }
        self.held()
            .blocks
            .get(&number)
            .map(|(timestamp, source)| Known::read(*timestamp, *source))
    }

    /// The timestamp of block `number`, if kept for good.
    pub(crate) fn kept_block(&self, number: u64) -> Option<u64> {
        let bytes = self.get(&self.blocks, &self.key(&number.to_be_bytes()))?;
        decode_u64(&bytes)
    }

    /// Every block timestamp kept for this vault, in block order.
    pub(crate) fn kept_blocks(&self) -> Vec<(u64, u64)> {
        let read = || -> heed::Result<Vec<(u64, u64)>> {
            let txn = self.store.env().read_txn()?;
            let mut blocks = Vec::new();
            for entry in self.blocks.prefix_iter(&txn, &self.vaults.v2[..])? {
                let (key, value) = entry?;
                let number = key
                    .get(20..28)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes);
                if let (Some(number), Some(timestamp)) = (number, decode_u64(value)) {
                    blocks.push((number, timestamp));
                }
            }
            Ok(blocks)
        };
        read().unwrap_or_else(|e| {
            debug!("Could not read the block timestamps kept: {e}");
            Vec::new()
        })
    }

    /// The payments of `quote_hash`, held or kept. Held ones come first: a
    /// quote is held again only after a search found payments the kept ones
    /// lack, and is held with the kept ones too, so it holds the most found.
    pub(crate) fn quote(&self, quote_hash: &[u8; 32]) -> Option<Known<Vec<VaultLog>>> {
        if let Some(payments) = self.held().quotes.get(quote_hash) {
            return Some(Known {
                value: payments.clone(),
                kept: false,
                source: None,
            });
        }
        self.kept_quote(quote_hash).map(|payments| Known {
            value: payments,
            kept: true,
            source: None,
        })
    }

    /// The payments of `quote_hash`, if kept for good.
    pub(crate) fn kept_quote(&self, quote_hash: &[u8; 32]) -> Option<Vec<VaultLog>> {
        let bytes = self.get(&self.quotes, &self.logs_key(quote_hash))?;
        decode_payments(&bytes)
    }

    /// The transaction of the vault's log at `log_index` in block `block`,
    /// kept or held.
    pub(crate) fn block_log(&self, block: u64, log_index: u64) -> Option<Known<[u8; 32]>> {
        if let Some(tx_hash) = self.kept_block_log(block, log_index) {
            return Some(Known {
                value: tx_hash,
                kept: true,
                source: None,
            });
        }
        self.held()
            .block_logs
            .get(&(block, log_index))
            .map(|tx_hash| Known {
                value: *tx_hash,
                kept: false,
                source: None,
            })
    }

    /// The transaction of the vault's log at `log_index` in block `block`,
    /// if kept for good.
    pub(crate) fn kept_block_log(&self, block: u64, log_index: u64) -> Option<[u8; 32]> {
        let bytes = self.get(&self.block_logs, &self.block_log_key(block, log_index))?;
        match bytes.split_first() {
            Some((&FORMAT, tx_hash)) => tx_hash.try_into().ok(),
            _ => None,
        }
    }

    /// Hold a receipt read through provider `source` until it can be kept.
    pub(crate) fn hold_receipt(&self, receipt: &PaymentReceipt, source: usize) {
        self.held()
            .receipts
            .insert(receipt.tx_hash, (receipt.clone(), source));
    }

    /// Hold a block timestamp read through provider `source`.
    pub(crate) fn hold_block(&self, number: u64, timestamp: u64, source: usize) {
        self.held().blocks.insert(number, (timestamp, source));
    }

    /// Hold the payments of `quote_hash` log queries found.
    pub(crate) fn hold_quote(&self, quote_hash: [u8; 32], payments: Vec<VaultLog>) {
        self.held().quotes.insert(quote_hash, payments);
    }

    /// Hold the transaction of the vault's log at a block and log index.
    pub(crate) fn hold_block_log(&self, block: u64, log_index: u64, tx_hash: [u8; 32]) {
        self.held().block_logs.insert((block, log_index), tx_hash);
    }

    /// Drop the held receipt of `tx_hash`.
    pub(crate) fn forget_receipt(&self, tx_hash: &[u8; 32]) {
        self.held().receipts.remove(tx_hash);
    }

    /// Drop the held timestamp of block `number`.
    pub(crate) fn forget_block(&self, number: u64) {
        self.held().blocks.remove(&number);
    }

    /// Drop the held payments of `quote_hash`.
    #[cfg(test)]
    pub(crate) fn forget_quote(&self, quote_hash: &[u8; 32]) {
        self.held().quotes.remove(quote_hash);
    }

    /// Drop the held transaction of a block's log.
    #[cfg(test)]
    pub(crate) fn forget_block_log(&self, block: u64, log_index: u64) {
        self.held().block_logs.remove(&(block, log_index));
    }

    /// How many facts are held, not kept yet.
    #[cfg(test)]
    pub(crate) fn held_count(&self) -> usize {
        let held = self.held();
        held.receipts.len() + held.blocks.len() + held.quotes.len() + held.block_logs.len()
    }

    /// The highest block any held fact is in, if any is held.
    pub(crate) fn highest_held(&self) -> Option<u64> {
        let held = self.held();
        held.receipts
            .values()
            .map(|(receipt, _)| receipt.block_number)
            .chain(held.blocks.keys().copied())
            .chain(held.quotes.values().flatten().map(|p| p.block_number))
            .chain(held.block_logs.keys().map(|(block, _)| *block))
            .max()
    }

    /// Take out the held receipts and block timestamps whose blocks are at
    /// or below `finalized`, each with the provider it was read through.
    #[allow(clippy::type_complexity)]
    pub(crate) fn take_final(
        &self,
        finalized: u64,
    ) -> (Vec<(PaymentReceipt, usize)>, Vec<(u64, u64, usize)>) {
        let mut held = self.held();
        let mut receipts = Vec::new();
        held.receipts.retain(|_, (receipt, source)| {
            let take = receipt.block_number <= finalized;
            if take {
                receipts.push((receipt.clone(), *source));
            }
            !take
        });
        let mut blocks = Vec::new();
        held.blocks.retain(|number, (timestamp, source)| {
            let take = *number <= finalized;
            if take {
                blocks.push((*number, *timestamp, *source));
            }
            !take
        });
        (receipts, blocks)
    }

    /// Take out the held quotes' payments and block logs whose blocks are all
    /// at or below `finalized`. A quote held with no payment is dropped: no
    /// payment is never kept.
    #[allow(clippy::type_complexity)]
    pub(crate) fn take_final_payments(
        &self,
        finalized: u64,
    ) -> (Vec<([u8; 32], Vec<VaultLog>)>, Vec<((u64, u64), [u8; 32])>) {
        let mut held = self.held();
        let mut quotes = Vec::new();
        held.quotes.retain(|quote_hash, payments| {
            let take = payments.iter().all(|p| p.block_number <= finalized);
            if take && !payments.is_empty() {
                quotes.push((*quote_hash, payments.clone()));
            }
            !take
        });
        let mut block_logs = Vec::new();
        held.block_logs.retain(|(block, log_index), tx_hash| {
            let take = *block <= finalized;
            if take {
                block_logs.push(((*block, *log_index), *tx_hash));
            }
            !take
        });
        (quotes, block_logs)
    }

    /// Keep `keep` for good, in one write, and drop what it keeps from what
    /// is held. False if the store couldn't be written: nothing is kept,
    /// and the facts are read again when next needed.
    pub(crate) fn keep(&self, keep: &Keep) -> bool {
        if keep.is_empty() {
            return true;
        }
        let write = || -> heed::Result<()> {
            let mut txn = self.store.env().write_txn()?;
            for receipt in &keep.receipts {
                if let Some(bytes) = encode_receipt(receipt, &self.vaults) {
                    self.receipts
                        .put(&mut txn, &self.logs_key(&receipt.tx_hash), &bytes)?;
                }
            }
            for (number, timestamp) in &keep.blocks {
                self.blocks.put(
                    &mut txn,
                    &self.key(&number.to_be_bytes()),
                    &encode_u64(*timestamp),
                )?;
            }
            // No payment found is "not found": never kept.
            for (quote_hash, payments) in keep.quotes.iter().filter(|(_, p)| !p.is_empty()) {
                if let Some(bytes) = encode_payments(payments) {
                    self.quotes
                        .put(&mut txn, &self.logs_key(quote_hash), &bytes)?;
                }
            }
            for ((block, log_index), tx_hash) in &keep.block_logs {
                let mut bytes = vec![FORMAT];
                bytes.extend_from_slice(tx_hash);
                self.block_logs
                    .put(&mut txn, &self.block_log_key(*block, *log_index), &bytes)?;
            }
            txn.commit()
        };
        if let Err(e) = write() {
            debug!("Could not keep chain facts: {e}");
            return false;
        }
        let mut held = self.held();
        for receipt in &keep.receipts {
            held.receipts.remove(&receipt.tx_hash);
        }
        for (number, _) in &keep.blocks {
            held.blocks.remove(number);
        }
        for (quote_hash, _) in &keep.quotes {
            held.quotes.remove(quote_hash);
        }
        for (block_log, _) in &keep.block_logs {
            held.block_logs.remove(block_log);
        }
        true
    }

    /// `id` keyed under the per-quote vault.
    fn key(&self, id: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(20 + id.len());
        key.extend_from_slice(&self.vaults.v2);
        key.extend_from_slice(id);
        key
    }

    /// `id` keyed under the vaults whose logs are read: the per-quote
    /// vault's alone as [`Self::key`], and with a root vault, its address and
    /// token after it. A receipt or a quote's payments read with a root vault
    /// hold logs a reader of the per-quote vault alone never reads, and those
    /// read without one lack them, so neither reads the other's.
    fn logs_key(&self, id: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(60 + id.len());
        key.extend_from_slice(&self.vaults.v2);
        if let Some(root) = self.vaults.root {
            key.extend_from_slice(&root.address);
            key.extend_from_slice(&root.token);
        }
        key.extend_from_slice(id);
        key
    }

    fn block_log_key(&self, block: u64, log_index: u64) -> Vec<u8> {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&block.to_be_bytes());
        id[8..].copy_from_slice(&log_index.to_be_bytes());
        self.key(&id)
    }
}

/// `receipt` as kept: [`RECEIPT_FORMAT`], success (0 or 1), the block (8
/// bytes, big endian), the number of logs (2 bytes), then each log a reader
/// of `vaults` keeps ([`receipt_keeps`]): its address (20 bytes), index (8
/// bytes), number of topics (1 byte), the topics (32 bytes each), the length
/// of its data (4 bytes) and the data. `None` if it has more logs, topics or
/// data than that holds.
fn encode_receipt(receipt: &PaymentReceipt, vaults: &VaultSet) -> Option<Vec<u8>> {
    let logs: Vec<&PaymentLog> = receipt
        .logs
        .iter()
        .filter(|log| receipt_keeps(vaults, &log.address))
        .collect();
    let mut bytes = vec![RECEIPT_FORMAT, u8::from(receipt.success)];
    bytes.extend_from_slice(&receipt.block_number.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(logs.len()).ok()?.to_be_bytes());
    for log in logs {
        bytes.extend_from_slice(&log.address);
        bytes.extend_from_slice(&log.log_index.to_be_bytes());
        bytes.push(u8::try_from(log.topics.len()).ok()?);
        for topic in &log.topics {
            bytes.extend_from_slice(topic);
        }
        bytes.extend_from_slice(&u32::try_from(log.data.len()).ok()?.to_be_bytes());
        bytes.extend_from_slice(&log.data);
    }
    Some(bytes)
}

/// A receipt kept for `tx_hash` ([`encode_receipt`]), as a reader of
/// `vaults` reads it. One of [`FORMAT`], whose logs are the per-quote vault's
/// with no data, is read only with no root vault. `None` for bytes of
/// another format, cut short, with bytes left over, or with a log the
/// reader doesn't keep.
fn decode_receipt(tx_hash: [u8; 32], vaults: &VaultSet, bytes: &[u8]) -> Option<PaymentReceipt> {
    let mut reader = Reader(bytes);
    let addressed = match reader.u8()? {
        RECEIPT_FORMAT => true,
        FORMAT if vaults.root.is_none() => false,
        _ => return None,
    };
    let success = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let block_number = reader.u64()?;
    let count = u16::from_be_bytes(reader.take()?);
    let mut logs = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let address = if addressed {
            reader.take::<20>()?
        } else {
            vaults.v2
        };
        if !receipt_keeps(vaults, &address) {
            return None;
        }
        let log_index = reader.u64()?;
        let topics = (0..reader.u8()?)
            .map(|_| reader.take::<32>())
            .collect::<Option<Vec<[u8; 32]>>>()?;
        let data = if addressed {
            let length = usize::try_from(u32::from_be_bytes(reader.take()?)).ok()?;
            let (data, rest) = reader.0.split_at_checked(length)?;
            reader.0 = rest;
            data.to_vec()
        } else {
            Vec::new()
        };
        logs.push(PaymentLog {
            address,
            topics,
            data,
            log_index,
        });
    }
    reader.0.is_empty().then_some(PaymentReceipt {
        tx_hash,
        success,
        block_number,
        logs,
    })
}

/// A quote's payments as kept: [`FORMAT`], how many (2 bytes), then each
/// one's transaction (32 bytes), block and log index (8 bytes each).
fn encode_payments(payments: &[VaultLog]) -> Option<Vec<u8>> {
    let mut bytes = vec![FORMAT];
    bytes.extend_from_slice(&u16::try_from(payments.len()).ok()?.to_be_bytes());
    for payment in payments {
        bytes.extend_from_slice(&payment.tx_hash);
        bytes.extend_from_slice(&payment.block_number.to_be_bytes());
        bytes.extend_from_slice(&payment.log_index.to_be_bytes());
    }
    Some(bytes)
}

/// A quote's payments kept ([`encode_payments`]).
fn decode_payments(bytes: &[u8]) -> Option<Vec<VaultLog>> {
    let mut reader = Reader(bytes);
    if reader.u8()? != FORMAT {
        return None;
    }
    let count = u16::from_be_bytes(reader.take()?);
    let payments = (0..count)
        .map(|_| {
            Some(VaultLog {
                tx_hash: reader.take()?,
                block_number: reader.u64()?,
                log_index: reader.u64()?,
            })
        })
        .collect::<Option<Vec<VaultLog>>>()?;
    reader.0.is_empty().then_some(payments)
}

fn encode_u64(value: u64) -> Vec<u8> {
    let mut bytes = vec![FORMAT];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes
}

fn decode_u64(bytes: &[u8]) -> Option<u64> {
    let mut reader = Reader(bytes);
    if reader.u8()? != FORMAT {
        return None;
    }
    let value = reader.u64()?;
    reader.0.is_empty().then_some(value)
}

/// Reads kept bytes front to back.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_at_checked(N)?;
        self.0 = rest;
        head.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[byte]| byte)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_be_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_listings::{RootVault, DATA_PAYMENT_MADE_TOPIC};

    const VAULT: [u8; 20] = [0x69; 20];
    const VAULTS: VaultSet = VaultSet::v2_only(VAULT);
    const ROOT: RootVault = RootVault {
        address: [0xf6; 20],
        token: [0x7a; 20],
    };

    fn store(dir: &std::path::Path) -> ListingsStore {
        ListingsStore::open_with_map_size(dir, 16 * 1024 * 1024).unwrap()
    }

    fn receipt() -> PaymentReceipt {
        PaymentReceipt {
            tx_hash: [0xaa; 32],
            success: true,
            block_number: 81_942_857,
            logs: vec![
                PaymentLog {
                    address: VAULT,
                    topics: vec![DATA_PAYMENT_MADE_TOPIC, [1; 32], [2; 32], [3; 32]],
                    data: Vec::new(),
                    log_index: 4,
                },
                PaymentLog {
                    address: VAULT,
                    topics: Vec::new(),
                    data: Vec::new(),
                    log_index: 9,
                },
            ],
        }
    }

    #[test]
    fn a_receipt_is_kept_as_the_vaults_logs_and_read_back_whole() {
        let mut with_others = receipt();
        with_others.logs.insert(
            0,
            PaymentLog {
                address: [0x11; 20],
                topics: vec![[5; 32]],
                data: Vec::new(),
                log_index: 1,
            },
        );
        let bytes = encode_receipt(&with_others, &VAULTS).unwrap();
        assert_eq!(decode_receipt([0xaa; 32], &VAULTS, &bytes), Some(receipt()));
        // Another format, cut short or with bytes over: nothing.
        let mut other = bytes.clone();
        other[0] = 3;
        assert_eq!(decode_receipt([0xaa; 32], &VAULTS, &other), None);
        for end in 0..bytes.len() {
            assert_eq!(decode_receipt([0xaa; 32], &VAULTS, &bytes[..end]), None);
        }
        let mut longer = bytes;
        longer.push(0);
        assert_eq!(decode_receipt([0xaa; 32], &VAULTS, &longer), None);
    }

    /// A receipt of the first format: the per-quote vault's logs, each its
    /// index and topics, with no address or data.
    fn first_format(receipt: &PaymentReceipt) -> Vec<u8> {
        let mut bytes = vec![FORMAT, u8::from(receipt.success)];
        bytes.extend_from_slice(&receipt.block_number.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(receipt.logs.len()).unwrap().to_be_bytes());
        for log in &receipt.logs {
            bytes.extend_from_slice(&log.log_index.to_be_bytes());
            bytes.push(u8::try_from(log.topics.len()).unwrap());
            for topic in &log.topics {
                bytes.extend_from_slice(topic);
            }
        }
        bytes
    }

    #[test]
    fn a_first_format_receipt_is_read_only_without_a_root_vault() {
        let bytes = first_format(&receipt());
        assert_eq!(decode_receipt([0xaa; 32], &VAULTS, &bytes), Some(receipt()));
        let with_root = VaultSet::with_root(VAULT, ROOT);
        assert_eq!(decode_receipt([0xaa; 32], &with_root, &bytes), None);
    }

    /// A root wave's receipt: a per-quote vault log, the root vault's
    /// payment and `RootPaid` logs, the token's transfer, each with its data,
    /// and another contract's log.
    fn root_receipt() -> PaymentReceipt {
        let log = |address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>, log_index| PaymentLog {
            address,
            topics,
            data,
            log_index,
        };
        PaymentReceipt {
            tx_hash: [0xcc; 32],
            success: true,
            block_number: 81_942_900,
            logs: vec![
                log(VAULT, vec![DATA_PAYMENT_MADE_TOPIC, [1; 32]], Vec::new(), 0),
                log(
                    ROOT.address,
                    vec![DATA_PAYMENT_MADE_TOPIC, [2; 32], [3; 32], [4; 32]],
                    Vec::new(),
                    1,
                ),
                log(ROOT.address, vec![[5; 32], [6; 32]], vec![7; 96], 2),
                log(
                    ROOT.token,
                    vec![[8; 32], [9; 32], [10; 32]],
                    vec![11; 32],
                    3,
                ),
                log([0x11; 20], vec![[12; 32]], vec![13; 4], 4),
            ],
        }
    }

    #[test]
    fn a_root_waves_receipt_is_kept_with_each_logs_address_and_data() {
        let dir = tempfile::tempdir().unwrap();
        let with_root = VaultSet::with_root(VAULT, ROOT);
        let mut expected = root_receipt();
        expected.logs.retain(|log| log.address != [0x11; 20]);
        {
            let facts = Facts::open(&store(dir.path()), with_root).unwrap();
            assert!(facts.keep(&Keep {
                receipts: vec![root_receipt()],
                ..Keep::default()
            }));
        }
        let store = store(dir.path());
        let facts = Facts::open(&store, with_root).unwrap();
        let kept = facts.receipt(&[0xcc; 32]).unwrap();
        assert!(kept.kept);
        assert_eq!(kept.value, expected);
        // A reader of the per-quote vault alone keeps its own: it never
        // reads one kept with a root vault, nor the other way round.
        let mut v2_only = Facts::open(&store, VAULTS).unwrap();
        assert!(v2_only.receipt(&[0xcc; 32]).is_none());
        assert!(v2_only.keep(&Keep {
            receipts: vec![receipt()],
            ..Keep::default()
        }));
        assert_eq!(v2_only.kept_receipt(&[0xaa; 32]), Some(receipt()));
        assert!(facts.receipt(&[0xaa; 32]).is_none());
        // Moving the reader to the root vault moves what it reads.
        v2_only.set_vaults(with_root);
        assert_eq!(v2_only.kept_receipt(&[0xcc; 32]), Some(expected));
        assert!(v2_only.receipt(&[0xaa; 32]).is_none());
    }

    /// Opening the store with a root vault drops the receipts and quotes'
    /// payments a reader of the per-quote vault alone kept, which it never
    /// reads, and keeps its own, the blocks and the block logs.
    #[test]
    fn a_root_reader_drops_the_facts_kept_for_the_per_quote_vault_alone() {
        let dir = tempfile::tempdir().unwrap();
        let with_root = VaultSet::with_root(VAULT, ROOT);
        let payments = vec![VaultLog {
            tx_hash: [0xaa; 32],
            block_number: 81_942_857,
            log_index: 4,
        }];
        let store = store(dir.path());
        {
            let v2_only = Facts::open(&store, VAULTS).unwrap();
            assert!(v2_only.keep(&Keep {
                receipts: vec![receipt()],
                blocks: vec![(81_942_857, 1_791_321_603)],
                quotes: vec![([3; 32], payments)],
                block_logs: vec![((81_942_857, 4), [0xaa; 32])],
            }));
            // A first-format receipt, as a reader kept it before receipts
            // held their logs' addresses and data.
            let mut txn = store.env().write_txn().unwrap();
            v2_only
                .receipts
                .put(
                    &mut txn,
                    &v2_only.key(&[0xbb; 32]),
                    &first_format(&receipt()),
                )
                .unwrap();
            txn.commit().unwrap();
        }
        // Another vault's facts are not this reader's to drop.
        let other = Facts::open(&store, VaultSet::v2_only([0x70; 20])).unwrap();
        assert!(other.keep(&Keep {
            receipts: vec![receipt()],
            ..Keep::default()
        }));
        let unrooted = |facts: &Facts| {
            let txn = store.env().read_txn().unwrap();
            [&facts.receipts, &facts.quotes]
                .into_iter()
                .map(|database| {
                    database
                        .prefix_iter(&txn, &VAULT[..])
                        .unwrap()
                        .filter(|entry| entry.as_ref().unwrap().0.len() == UNROOTED_KEY_LEN)
                        .count()
                })
                .sum::<usize>()
        };
        let rooted = Facts::open(&store, with_root).unwrap();
        assert_eq!(unrooted(&rooted), 0);
        assert!(rooted.keep(&Keep {
            receipts: vec![root_receipt()],
            ..Keep::default()
        }));
        assert!(rooted.kept_receipt(&[0xcc; 32]).is_some());
        assert_eq!(rooted.kept_blocks(), vec![(81_942_857, 1_791_321_603)]);
        assert_eq!(rooted.kept_block_log(81_942_857, 4), Some([0xaa; 32]));
        assert!(other.kept_receipt(&[0xaa; 32]).is_some());
        // A reader moved to the root vault drops them the same way, and
        // keeps the root vault's.
        let mut moved = Facts::open(&store, VAULTS).unwrap();
        assert!(moved.keep(&Keep {
            receipts: vec![receipt()],
            ..Keep::default()
        }));
        assert_eq!(unrooted(&moved), 1);
        moved.set_vaults(with_root);
        assert_eq!(unrooted(&moved), 0);
        assert!(moved.kept_receipt(&[0xcc; 32]).is_some());
    }

    #[test]
    fn payments_and_timestamps_are_kept_whole() {
        let payments = vec![
            VaultLog {
                tx_hash: [7; 32],
                block_number: 150,
                log_index: 4,
            },
            VaultLog {
                tx_hash: [8; 32],
                block_number: 151,
                log_index: 0,
            },
        ];
        let bytes = encode_payments(&payments).unwrap();
        assert_eq!(decode_payments(&bytes), Some(payments));
        assert_eq!(decode_payments(&bytes[..bytes.len() - 1]), None);
        assert_eq!(
            decode_payments(&encode_payments(&[]).unwrap()),
            Some(Vec::new())
        );
        assert_eq!(decode_u64(&encode_u64(1_791_321_603)), Some(1_791_321_603));
        assert_eq!(decode_u64(&[FORMAT, 1, 2]), None);
    }

    #[test]
    fn facts_kept_are_read_back_after_a_restart_and_only_for_their_vault() {
        let dir = tempfile::tempdir().unwrap();
        let payments = vec![VaultLog {
            tx_hash: [0xaa; 32],
            block_number: 81_942_857,
            log_index: 4,
        }];
        {
            let facts = Facts::open(&store(dir.path()), VAULTS).unwrap();
            // Held, not kept.
            facts.hold_receipt(&receipt(), 1);
            facts.hold_block(81_942_857, 1_791_321_603, 1);
            facts.hold_quote([3; 32], payments.clone());
            facts.hold_block_log(81_942_857, 4, [0xaa; 32]);
            assert_eq!(facts.held_count(), 4);
            let held = facts.receipt(&[0xaa; 32]).unwrap();
            assert!(!held.kept);
            assert_eq!(held.source, Some(1));
            assert_eq!(facts.kept_receipt(&[0xaa; 32]), None);
            // Kept: no longer held.
            assert!(facts.keep(&Keep {
                receipts: vec![receipt()],
                blocks: vec![(81_942_857, 1_791_321_603)],
                quotes: vec![([3; 32], payments.clone())],
                block_logs: vec![((81_942_857, 4), [0xaa; 32])],
            }));
            assert_eq!(facts.held_count(), 0);
        }
        let store = store(dir.path());
        let facts = Facts::open(&store, VAULTS).unwrap();
        let kept = facts.receipt(&[0xaa; 32]).unwrap();
        assert!(kept.kept);
        assert_eq!(kept.value, receipt());
        assert_eq!(facts.block(81_942_857).unwrap().value, 1_791_321_603);
        assert_eq!(facts.kept_blocks(), vec![(81_942_857, 1_791_321_603)]);
        assert_eq!(facts.kept_quote(&[3; 32]), Some(payments));
        assert_eq!(facts.kept_block_log(81_942_857, 4), Some([0xaa; 32]));
        // Another vault's reader sees none of them.
        let other = Facts::open(&store, VaultSet::v2_only([0x70; 20])).unwrap();
        assert!(other.receipt(&[0xaa; 32]).is_none());
        assert!(other.block(81_942_857).is_none());
        assert!(other.kept_blocks().is_empty());
        assert!(other.quote(&[3; 32]).is_none());
        assert!(other.block_log(81_942_857, 4).is_none());
    }

    #[test]
    fn held_facts_can_be_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let facts = Facts::open(&store(dir.path()), VAULTS).unwrap();
        facts.hold_receipt(&receipt(), 0);
        facts.hold_block(5, 6, 0);
        facts.hold_quote([3; 32], Vec::new());
        facts.hold_block_log(5, 4, [1; 32]);
        facts.forget_receipt(&[0xaa; 32]);
        facts.forget_block(5);
        facts.forget_quote(&[3; 32]);
        facts.forget_block_log(5, 4);
        assert_eq!(facts.held_count(), 0);
    }
}
