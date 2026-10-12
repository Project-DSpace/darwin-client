//! Read back the vault's record of every quote a per-chunk payment paid.
//!
//! The DARWIN vault writes a quote hash's payment record once and skips a later
//! payment for the same hash, with no revert, no event and no transfer. Anyone
//! who knows a quote hash before it is paid (realistically the node that issued
//! the quote) can record it first with a dust payment to an address of its own.
//! The real payment is then skipped, and nodes refuse the chunk because the
//! record holds the wrong amount and rewards address. So after a payment the
//! upload reads each paid quote's record back, and a chunk whose record isn't
//! its own is quoted again (a fresh quote has a new hash, so a clean record)
//! and paid again, up to [`MAX_OCCUPIED_REQUOTES`] times.

use super::batch::ChunkPaymentPlan;
use super::Client;
use crate::data::error::Error;
use ant_protocol::evm::{Amount, EncodedPeerId, QuoteHash, RewardsAddress};
use ant_protocol::XorName;
#[cfg(any(feature = "native", test))]
use std::collections::HashMap;

/// How many times a chunk is quoted again after its paid quote turned out to be
/// occupied, before the upload stops.
pub const MAX_OCCUPIED_REQUOTES: usize = 3;

/// Starts the message of the error an upload stops with when a chunk's quotes
/// keep being occupied, so callers can recognise it.
pub const QUOTES_OCCUPIED: &str = "quotes occupied";

/// What the vault records for a quote hash: the first 16 bytes of the rewards
/// address it paid, and the amount. An amount of zero means no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultRecord {
    /// `bytes16(uint128(uint160(rewardsAddress) >> 32))`, the address's first 16 bytes.
    pub rewards_prefix: [u8; 16],
    /// Amount recorded, in atto.
    pub amount: Amount,
}

impl VaultRecord {
    /// Whether this record is a payment of at least `amount` to `rewards_address`.
    #[must_use]
    pub fn pays(&self, rewards_address: &RewardsAddress, amount: Amount) -> bool {
        !self.amount.is_zero()
            && self.amount >= amount
            && self.rewards_prefix[..] == rewards_address.as_slice()[..16]
    }
}

/// A paid quote whose vault record belongs to someone else: the payment for it
/// was skipped and moved no tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccupiedQuote {
    /// The chunk the quote was for.
    pub address: XorName,
    /// The occupied quote hash.
    pub quote_hash: QuoteHash,
    /// The node that issued the quote.
    pub issuer: EncodedPeerId,
    /// The quote's rewards address, which the payment was for.
    pub rewards_address: RewardsAddress,
    /// The amount the skipped payment was for.
    pub amount: Amount,
    /// What the vault holds for the quote hash instead.
    pub recorded: VaultRecord,
}

/// The non-zero quotes of `plans`, the ones a `payForQuotes` call pays.
#[cfg(any(feature = "native", test))]
pub(crate) fn paid_quotes(plans: &[ChunkPaymentPlan]) -> Vec<QuoteHash> {
    plans
        .iter()
        .flat_map(|plan| plan.payment.quotes.iter())
        .filter(|quote| !quote.amount.is_zero())
        .map(|quote| quote.quote_hash)
        .collect()
}

/// The paid quotes of `plans` whose record in `records` isn't the payment. A
/// quote with no record, or none in `records`, isn't counted: an RPC behind the
/// chain can show a confirmed payment's record as empty for a while, and paying
/// again for it would pay twice.
#[cfg(any(feature = "native", test))]
pub(crate) fn occupied_in(
    plans: &[ChunkPaymentPlan],
    records: &HashMap<QuoteHash, VaultRecord>,
) -> Vec<OccupiedQuote> {
    let mut occupied = Vec::new();
    for plan in plans {
        for quote in plan.payment.quotes.iter().filter(|q| !q.amount.is_zero()) {
            let Some(record) = records.get(&quote.quote_hash) else {
                continue;
            };
            if record.amount.is_zero() || record.pays(&quote.rewards_address, quote.amount) {
                continue;
            }
            let issuer = plan
                .peer_quotes
                .iter()
                .find(|(_, q)| q.hash() == quote.quote_hash)
                .map_or(EncodedPeerId::new([0; 32]), |(peer, _)| peer.clone());
            occupied.push(OccupiedQuote {
                address: plan.address,
                quote_hash: quote.quote_hash,
                issuer,
                rewards_address: quote.rewards_address,
                amount: quote.amount,
                recorded: *record,
            });
        }
    }
    occupied
}

/// The amount of the payments `occupied` lists, which the vault skipped.
pub(crate) fn skipped_amount(occupied: &[OccupiedQuote]) -> Amount {
    occupied
        .iter()
        .fold(Amount::ZERO, |sum, quote| sum.saturating_add(quote.amount))
}

/// The error for chunks quoted again [`MAX_OCCUPIED_REQUOTES`] times whose
/// quote was occupied every time. `history` holds every occupied quote met for
/// them, oldest first; the error names the nodes that issued them, most often
/// first.
pub(crate) fn occupied_error(history: &[OccupiedQuote]) -> Error {
    let mut by_issuer: Vec<(EncodedPeerId, RewardsAddress, usize)> = Vec::new();
    for quote in history {
        match by_issuer
            .iter_mut()
            .find(|(peer, _, _)| *peer == quote.issuer)
        {
            Some((_, _, count)) => *count += 1,
            None => by_issuer.push((quote.issuer.clone(), quote.rewards_address, 1)),
        }
    }
    by_issuer.sort_by_key(|issuer| std::cmp::Reverse(issuer.2));
    let nodes = by_issuer
        .iter()
        .map(|(peer, rewards, count)| {
            format!(
                "node {} (rewards address {rewards:#x}) issued {count}",
                hex::encode(peer.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut chunks = history.iter().map(|q| q.address).collect::<Vec<_>>();
    chunks.sort_unstable();
    chunks.dedup();
    let last = history.last().map(|q| {
        format!(
            "; the last, {:#x}, is recorded as {} atto to an address starting 0x{}",
            q.quote_hash,
            q.recorded.amount,
            hex::encode(q.recorded.rewards_prefix)
        )
    });
    Error::Payment(format!(
        "{QUOTES_OCCUPIED}: the vault already held another payment's record for {} paid quote(s) \
         of {} chunk(s), so those payments were skipped and moved no tokens; after {} fresh \
         quotes the chunk(s) are still unpaid. Occupied quotes: {nodes}{}",
        history.len(),
        chunks.len(),
        MAX_OCCUPIED_REQUOTES,
        last.unwrap_or_default()
    ))
}

impl Client {
    /// Read back the vault record of every paid quote in `plans`, and return
    /// the quotes whose record isn't the payment.
    ///
    /// Reads are retried for up to 8 seconds while a record is still empty,
    /// since an RPC can lag the chain. A quote whose record stays empty, or can't be
    /// read, is not reported: the upload then goes on as it would have without
    /// the read-back, and nodes decide. Without an EVM network (a client
    /// with neither `with_wallet` nor `with_evm_network`) nothing is read.
    #[cfg(feature = "native")]
    pub(crate) async fn occupied_quotes(&self, plans: &[ChunkPaymentPlan]) -> Vec<OccupiedQuote> {
        use ant_protocol::evm::contract::payment_vault::interface::IPaymentVault;
        use futures::StreamExt;

        /// Reads while some records are still empty, and the pause between
        /// them: as the console and the `dspace` CLI read records back.
        const READS: usize = 5;
        const PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

        let Some(network) = self.evm_network.as_ref() else {
            tracing::debug!("no EVM network configured: payment records not read back");
            return Vec::new();
        };
        let provider = ant_protocol::evm::utils::http_provider(network.rpc_url().clone());
        let vault = IPaymentVault::new(*network.payment_vault_address(), provider);
        let mut pending = paid_quotes(plans);
        let mut records = HashMap::new();
        for read in 0..READS {
            if pending.is_empty() {
                break;
            }
            if read > 0 {
                crate::runtime::sleep(PAUSE).await;
            }
            let read = futures::stream::iter(pending.iter().copied())
                .map(|hash| {
                    let vault = &vault;
                    async move { (hash, vault.completedPayments(hash).call().await) }
                })
                .buffer_unordered(16)
                .collect::<Vec<_>>()
                .await;
            pending.clear();
            for (hash, result) in read {
                match result {
                    Ok(record) if record.amount != 0 => {
                        records.insert(
                            hash,
                            VaultRecord {
                                rewards_prefix: record.rewardsAddress.0,
                                amount: Amount::from(record.amount),
                            },
                        );
                    }
                    Ok(_) => pending.push(hash),
                    Err(error) => {
                        tracing::debug!("reading the vault record of {hash:#x} failed: {error}");
                        pending.push(hash);
                    }
                }
            }
        }
        if !pending.is_empty() {
            tracing::warn!(
                "the vault showed no record for {} paid quote(s) after the payment; storing \
                 them as paid",
                pending.len()
            );
        }
        occupied_in(plans, &records)
    }

    /// Browser builds read no records back: the wallet callback owns the RPC.
    #[cfg(not(feature = "native"))]
    pub(crate) async fn occupied_quotes(&self, _plans: &[ChunkPaymentPlan]) -> Vec<OccupiedQuote> {
        Vec::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::data::client::batch::SingleNodeQuotePayment;
    use ant_protocol::evm::PaymentQuote;
    use std::time::SystemTime;

    fn quote(seed: u8, price: u64, content: [u8; 32]) -> PaymentQuote {
        PaymentQuote {
            content: xor_name::XorName(content),
            timestamp: SystemTime::now(),
            price: Amount::from(price),
            rewards_address: RewardsAddress::new([seed; 20]),
            pub_key: vec![seed; 4],
            signature: vec![seed; 4],
            committed_key_count: 0,
            commitment_pin: None,
        }
    }

    fn plan(address: u8) -> ChunkPaymentPlan {
        let quotes = (1..=5)
            .map(|seed| quote(seed, 10 * u64::from(seed), [address; 32]))
            .collect::<Vec<_>>();
        ChunkPaymentPlan {
            address: [address; 32],
            data_size: 1,
            quoted_peers: Vec::new(),
            payment: SingleNodeQuotePayment::from_quotes(quotes.clone()).unwrap(),
            peer_quotes: quotes
                .into_iter()
                .map(|q| (EncodedPeerId::new([q.rewards_address.0[0]; 32]), q))
                .collect(),
            commitment_sidecars: Vec::new(),
        }
    }

    fn paid(plan: &ChunkPaymentPlan) -> (QuoteHash, RewardsAddress, Amount) {
        let q = plan
            .payment
            .quotes
            .iter()
            .find(|q| !q.amount.is_zero())
            .unwrap();
        (q.quote_hash, q.rewards_address, q.amount)
    }

    fn record(rewards: &RewardsAddress, amount: Amount) -> VaultRecord {
        VaultRecord {
            rewards_prefix: rewards.as_slice()[..16].try_into().unwrap(),
            amount,
        }
    }

    #[test]
    fn only_records_of_another_payment_are_occupied() {
        let plans = [plan(1), plan(2), plan(3), plan(4)];
        let stranger = RewardsAddress::new([0xee; 20]);
        let mut records = HashMap::new();
        // Ours: the quote's rewards address and amount.
        let (hash, rewards, amount) = paid(&plans[0]);
        records.insert(hash, record(&rewards, amount));
        // Dust to the occupier's own address.
        let (hash, _, _) = paid(&plans[1]);
        records.insert(hash, record(&stranger, Amount::from(1u64)));
        // The quote's address, but less than the quote.
        let (hash, rewards, amount) = paid(&plans[2]);
        records.insert(hash, record(&rewards, amount - Amount::from(1u64)));
        // No record yet (an RPC behind the chain): not occupied.
        let (hash, _, _) = paid(&plans[3]);
        records.insert(hash, record(&stranger, Amount::ZERO));

        let occupied = occupied_in(&plans, &records);
        let addresses = occupied.iter().map(|q| q.address).collect::<Vec<_>>();
        assert_eq!(addresses, vec![[2; 32], [3; 32]]);
        let first = &occupied[0];
        assert_eq!(first.quote_hash, paid(&plans[1]).0);
        assert_eq!(first.amount, paid(&plans[1]).2);
        assert_eq!(first.recorded.amount, Amount::from(1u64));
        // The issuer is the peer whose signed quote carries the occupied hash.
        let issuer = plans[1]
            .peer_quotes
            .iter()
            .find(|(_, q)| q.hash() == first.quote_hash)
            .unwrap()
            .0
            .clone();
        assert_eq!(first.issuer, issuer);
        assert_eq!(
            skipped_amount(&occupied),
            paid(&plans[1]).2 + paid(&plans[2]).2
        );
    }

    #[test]
    fn a_larger_payment_to_the_quotes_address_is_ours() {
        let plans = [plan(7)];
        let (hash, rewards, amount) = paid(&plans[0]);
        let records = HashMap::from([(hash, record(&rewards, amount + Amount::from(5u64)))]);
        assert!(occupied_in(&plans, &records).is_empty());
    }

    #[test]
    fn the_error_names_the_node_whose_quotes_keep_being_occupied() {
        let plans = [plan(9)];
        let stranger = RewardsAddress::new([0xee; 20]);
        let (hash, _, _) = paid(&plans[0]);
        let records = HashMap::from([(hash, record(&stranger, Amount::from(1u64)))]);
        let occupied = occupied_in(&plans, &records);
        let history = [occupied.clone(), occupied.clone(), occupied].concat();
        let Error::Payment(message) = occupied_error(&history) else {
            panic!("not a payment error");
        };
        assert!(message.starts_with(QUOTES_OCCUPIED), "{message}");
        let issuer = hex::encode(history[0].issuer.as_bytes());
        assert!(message.contains(&format!("node {issuer}")), "{message}");
        assert!(message.contains("issued 3"), "{message}");
        assert!(message.contains("1 chunk(s)"), "{message}");
        assert!(message.contains(&hex::encode([0xee; 16])), "{message}");
    }
}
