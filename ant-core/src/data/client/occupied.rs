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
#[cfg(feature = "native")]
use super::listings::ListingChain;
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
    /// The records are read through the payment network's RPC and then the
    /// RPCs reads of payments fall back to ([`crate::config::fallback_rpc_urls`]:
    /// the bundled network's, none for any other), each call within its own
    /// time limit, as a [`ListingChain`] reads. A record still empty is read
    /// again, up to 5 reads 2 seconds apart, since an RPC can lag the chain. A
    /// quote whose record stays empty, or that no RPC answers for, is not
    /// reported: the upload then goes on as it would have without the
    /// read-back, and nodes decide. Without an EVM network (a client with
    /// neither `with_wallet` nor `with_evm_network`) nothing is read.
    #[cfg(feature = "native")]
    pub(crate) async fn occupied_quotes(&self, plans: &[ChunkPaymentPlan]) -> Vec<OccupiedQuote> {
        let Some(network) = self.evm_network.as_ref() else {
            tracing::debug!("no EVM network configured: payment records not read back");
            return Vec::new();
        };
        match ListingChain::new(network) {
            Ok(chain) => occupied_quotes_via(&chain, plans).await,
            Err(error) => {
                tracing::warn!(
                    "cannot read payment records back ({error}); storing the paid quotes as paid"
                );
                Vec::new()
            }
        }
    }

    /// Browser builds read no records back: the wallet callback owns the RPC.
    #[cfg(not(feature = "native"))]
    pub(crate) async fn occupied_quotes(&self, _plans: &[ChunkPaymentPlan]) -> Vec<OccupiedQuote> {
        Vec::new()
    }
}

/// [`Client::occupied_quotes`], reading through `chain`.
#[cfg(feature = "native")]
pub(crate) async fn occupied_quotes_via(
    chain: &ListingChain,
    plans: &[ChunkPaymentPlan],
) -> Vec<OccupiedQuote> {
    use futures::StreamExt;

    /// Reads while some records are still empty, and the pause between
    /// them.
    const READS: usize = 5;
    const PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

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
            .map(|hash| async move { (hash, chain.completed_payment(&hash).await) })
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await;
        pending.clear();
        for (hash, result) in read {
            match result {
                Ok(record) if !record.amount.is_zero() => {
                    records.insert(hash, record);
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

    /// How a mock RPC answers the vault reads.
    #[cfg(feature = "native")]
    #[derive(Clone, Copy)]
    enum Rpc {
        /// HTTP 403, as PublicNode refuses methods it doesn't serve.
        Forbidden,
        /// A JSON-RPC error of this code, such as -32005 over a request
        /// limit.
        Failing(i64),
        /// Answers from the records it holds.
        Answering,
    }

    /// A mock payment chain whose vault holds `records`, answering as `rpc`
    /// says; its URL, and the chain to count its calls.
    #[cfg(feature = "native")]
    async fn vault_rpc(
        rpc: Rpc,
        records: &[(QuoteHash, VaultRecord)],
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<crate::data::client::listings::test_chain::MockChain>>,
    ) {
        use crate::data::client::listings::test_chain::{serve, MockChain};
        let mut chain = MockChain::default();
        match rpc {
            Rpc::Forbidden => chain.refused = vec!["eth_call"],
            Rpc::Failing(code) => chain.failing = vec![("eth_call", code)],
            Rpc::Answering => {}
        }
        for (hash, record) in records {
            chain
                .vault_records
                .insert(hash.0, (record.rewards_prefix, record.amount.to::<u128>()));
        }
        let chain = std::sync::Arc::new(std::sync::Mutex::new(chain));
        (serve(std::sync::Arc::clone(&chain)).await, chain)
    }

    /// A reader of the test vault through `urls`, first to last.
    #[cfg(feature = "native")]
    fn reader(urls: Vec<String>) -> ListingChain {
        ListingChain::with_rpcs(urls, crate::data::client::listings::test_chain::VAULT).unwrap()
    }

    /// The first RPC refuses the read, as a provider that doesn't serve
    /// `eth_call` or is over its limit does; the next one holds a
    /// stranger's record, and the quote is reported occupied.
    #[cfg(feature = "native")]
    #[tokio::test]
    async fn a_record_the_first_rpc_refuses_is_read_from_the_next() {
        let plans = [plan(1)];
        let (hash, _, _) = paid(&plans[0]);
        let stranger = RewardsAddress::new([0xee; 20]);
        let dust = record(&stranger, Amount::from(1u64));
        for refusal in [Rpc::Forbidden, Rpc::Failing(-32_005)] {
            let (first, first_chain) = vault_rpc(refusal, &[]).await;
            let (second, second_chain) = vault_rpc(Rpc::Answering, &[(hash, dust)]).await;
            let occupied = occupied_quotes_via(&reader(vec![first, second]), &plans).await;
            assert_eq!(occupied.len(), 1);
            assert_eq!(occupied[0].address, [1; 32]);
            assert_eq!(occupied[0].quote_hash, hash);
            assert_eq!(occupied[0].recorded, dust);
            assert_eq!(first_chain.lock().unwrap().calls_to("eth_call"), 1);
            assert_eq!(second_chain.lock().unwrap().calls_to("eth_call"), 1);
        }
    }

    /// The first RPC can't be reached or fails the call; the next one holds
    /// the payment's own record, and nothing is reported.
    #[cfg(feature = "native")]
    #[tokio::test]
    async fn the_payments_own_record_from_the_next_rpc_is_not_occupied() {
        let plans = [plan(2)];
        let (hash, rewards, amount) = paid(&plans[0]);
        let ours = record(&rewards, amount);
        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            format!("http://{}", listener.local_addr().unwrap())
        };
        let (failing, _) = vault_rpc(Rpc::Failing(-32_000), &[]).await;
        for first in [closed, failing] {
            let (second, second_chain) = vault_rpc(Rpc::Answering, &[(hash, ours)]).await;
            let occupied = occupied_quotes_via(&reader(vec![first, second]), &plans).await;
            assert!(occupied.is_empty(), "{occupied:?}");
            assert_eq!(second_chain.lock().unwrap().calls_to("eth_call"), 1);
        }
    }

    /// No RPC answers: every read fails, 5 times 2 seconds apart, and the
    /// quote is not reported, so the upload goes on and nodes decide.
    #[cfg(feature = "native")]
    #[tokio::test]
    async fn nothing_is_reported_when_no_rpc_answers() {
        let plans = [plan(3)];
        let (forbidden, forbidden_chain) = vault_rpc(Rpc::Forbidden, &[]).await;
        let (limited, limited_chain) = vault_rpc(Rpc::Failing(-32_005), &[]).await;
        let started = std::time::Instant::now();
        let occupied = occupied_quotes_via(&reader(vec![forbidden, limited]), &plans).await;
        assert!(occupied.is_empty(), "{occupied:?}");
        assert!(started.elapsed() >= std::time::Duration::from_secs(8));
        assert_eq!(forbidden_chain.lock().unwrap().calls_to("eth_call"), 5);
        assert_eq!(limited_chain.lock().unwrap().calls_to("eth_call"), 5);
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
