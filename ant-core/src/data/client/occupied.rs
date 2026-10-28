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

#[cfg(any(feature = "native", test))]
use super::batch::PaidChunk;
#[cfg(feature = "native")]
use super::batch::SingleNodeQuotePayment;
use super::batch::{ChunkPaymentPlan, PreparedChunk};
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
        // A root wave's quotes have no record of their own: its key's
        // record binds each leaf's payee and amount, and is read instead.
        .filter(|plan| plan.vault.is_v2())
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
    for plan in plans.iter().filter(|plan| plan.vault.is_v2()) {
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
    Error::Payment(occupied_message(
        history,
        "chunk",
        &format!("after {MAX_OCCUPIED_REQUOTES} fresh quotes the chunk(s) are still unpaid"),
    ))
}

/// The error for chunks an outside payer paid whose quote was occupied, found
/// when the upload is finalized: named as [`occupied_error`] names them, but a
/// finalize can't quote them again, so they are never sent.
pub(crate) fn occupied_at_finalize(history: &[OccupiedQuote]) -> Error {
    Error::Payment(occupied_message(
        history,
        "chunk",
        "a finalize can't quote them again, so the chunk(s) are unpaid and were not sent: \
         prepare the upload again to quote and pay them afresh",
    ))
}

/// The error for a pointer state stored with a paid proof whose quote was
/// occupied: named as [`occupied_error`] names it, refused before the state
/// is sent.
#[cfg(any(feature = "native", test))]
pub(crate) fn occupied_pointer_proof(history: &[OccupiedQuote]) -> Error {
    Error::Payment(occupied_message(
        history,
        "pointer state",
        "the state is unpaid and was not sent: quote it again (prepare_pointer_payment) and \
         pay the new quote",
    ))
}

/// The message of the errors above: how many paid quotes of how many records
/// (`kind`, such as "chunk") were occupied, what became of the records
/// (`unpaid`), and the nodes that issued the quotes.
fn occupied_message(history: &[OccupiedQuote], kind: &str, unpaid: &str) -> String {
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
    format!(
        "{QUOTES_OCCUPIED}: the vault already held another payment's record for {} paid quote(s) \
         of {} {kind}(s), so those payments were skipped and moved no tokens; {unpaid}. \
         Occupied quotes: {nodes}{}",
        history.len(),
        chunks.len(),
        last.unwrap_or_default()
    )
}

/// The payment plan of each of `prepared`, to read its paid quote back once
/// a payer outside this client has paid it.
pub(crate) fn plans_of(prepared: &[PreparedChunk]) -> Vec<ChunkPaymentPlan> {
    prepared
        .iter()
        .map(|chunk| ChunkPaymentPlan {
            address: chunk.address,
            data_size: chunk.content.len() as u64,
            quoted_peers: Vec::new(),
            payment: chunk.payment.clone(),
            peer_quotes: chunk.peer_quotes.clone(),
            commitment_sidecars: Vec::new(),
            vault: crate::data::client::root_payment::PaymentVault::V2,
        })
        .collect()
}

/// Take out of `paid` the chunks whose paid quote is in `occupied`: the vault
/// skipped those payments, so nodes would refuse the chunks. Returns the
/// chunks to store, and each chunk taken out with why
/// ([`occupied_at_finalize`], naming its own occupied quotes).
#[cfg(any(feature = "native", test))]
pub(crate) fn set_aside_occupied(
    paid: Vec<PaidChunk>,
    occupied: &[OccupiedQuote],
) -> (Vec<PaidChunk>, Vec<([u8; 32], String)>) {
    let mut kept = Vec::with_capacity(paid.len());
    let mut unpaid = Vec::new();
    for chunk in paid {
        let met: Vec<OccupiedQuote> = occupied
            .iter()
            .filter(|quote| quote.address == chunk.address)
            .cloned()
            .collect();
        if met.is_empty() {
            kept.push(chunk);
        } else {
            unpaid.push((chunk.address, occupied_at_finalize(&met).to_string()));
        }
    }
    (kept, unpaid)
}

/// The payment plan a single-node payment proof was paid from, for the
/// record it pays for (`address`: a chunk's address, or a pointer's state)
/// of `weight`: the quotes it carries, the median paid three times its price
/// times `weight`, as [`SingleNodeQuotePayment::from_quotes`] plans them. A
/// vault record of at least that amount is the payment, so a proof paid at a
/// full chunk's amount reads as paid too.
///
/// # Errors
///
/// Returns why if the proof isn't a single-node proof, or its quotes can't be
/// planned.
#[cfg(feature = "native")]
pub(crate) fn plan_of_proof(
    address: XorName,
    data_size: u64,
    weight: ant_protocol::payment::pricing::RecordWeight,
    proof: &[u8],
) -> Result<ChunkPaymentPlan, String> {
    use ant_protocol::payment::{detect_proof_type, ProofType};
    let (proof, vault) = match detect_proof_type(proof) {
        Some(ProofType::SingleNode) => (
            ant_protocol::payment::deserialize_proof(proof)?.0,
            super::root_payment::PaymentVault::V2,
        ),
        Some(ProofType::Root) => (
            ant_protocol::payment::deserialize_root_proof(proof)?
                .payment
                .proof_of_payment,
            super::root_payment::PaymentVault::Root,
        ),
        Some(ProofType::Merkle) | None => {
            return Err("not a single-node or root payment proof".into());
        }
    };
    let quotes = proof
        .peer_quotes
        .iter()
        .map(|(_, quote)| quote.clone())
        .collect();
    let payment = SingleNodeQuotePayment::from_quotes(quotes, weight).map_err(|e| e.to_string())?;
    Ok(ChunkPaymentPlan {
        address,
        data_size,
        quoted_peers: Vec::new(),
        payment,
        peer_quotes: proof.peer_quotes,
        commitment_sidecars: Vec::new(),
        vault,
    })
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
    /// neither `with_wallet` nor `with_evm_network`) nothing is read, and a
    /// warning says so whenever there are paid quotes to read.
    #[cfg(feature = "native")]
    pub(crate) async fn occupied_quotes(&self, plans: &[ChunkPaymentPlan]) -> Vec<OccupiedQuote> {
        let Some(network) = self.evm_network.as_ref() else {
            if !plans.is_empty() {
                tracing::warn!(
                    "no EVM network configured (with_wallet or with_evm_network): the vault \
                     records of {} paid record(s) are not read back",
                    plans.len()
                );
            }
            return Vec::new();
        };
        match read_back_chain(network) {
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

    /// Read back the vault's record of the payment a kept single-node
    /// `proof` carries, before the record it pays for is paid again because
    /// every storer refused the proof. Read as [`Self::occupied_quotes`]
    /// reads, through the payment network's RPC and those it falls back to,
    /// up to 3 times 2 seconds apart while no RPC answers.
    ///
    /// A root proof's payment can only be in the root vault: the vault's
    /// record under the key its leaf and path lead to is read, and re-read
    /// while empty ([`Self::root_wave_recorded`]). It is never judged by the
    /// per-quote vault's records, nor a single-node proof by the root
    /// vault's.
    #[cfg(feature = "native")]
    pub(crate) async fn kept_payment(&self, proof: &[u8]) -> KeptPayment {
        use ant_protocol::payment::{detect_proof_type, ProofType};
        match detect_proof_type(proof) {
            Some(ProofType::SingleNode) => {}
            Some(ProofType::Root) => {
                let Some(vault) = self.root_vault() else {
                    return KeptPayment::NotChecked;
                };
                let Some(key) = ant_protocol::payment::deserialize_root_proof(proof)
                    .ok()
                    .and_then(|proof| super::root_payment::proof_key(&proof, &vault))
                else {
                    return KeptPayment::NotChecked;
                };
                return self.root_wave_recorded(&vault, &key, 2).await;
            }
            Some(ProofType::Merkle) | None => return KeptPayment::NotChecked,
        }
        let Some(network) = self.evm_network.as_ref() else {
            return KeptPayment::NotChecked;
        };
        let Some((_, hash, rewards)) = super::upload_state::paid_quote(proof) else {
            return KeptPayment::NotChecked;
        };
        let chain = match read_back_chain(network) {
            Ok(chain) => chain,
            Err(error) => {
                tracing::warn!("cannot read the kept proof's payment record ({error})");
                return KeptPayment::Unreadable;
            }
        };
        match read_record(&chain, &hash).await {
            Some(record) if records_payment_to(&record, &rewards) => KeptPayment::Recorded,
            Some(_) => KeptPayment::NotRecorded,
            None => KeptPayment::Unreadable,
        }
    }

    /// Read back the vault's record of each of `quotes`, a shared wave
    /// member's, whose wave's file is gone, before the member is taken to
    /// have had nothing signed for it and pays afresh: `Recorded` if any is
    /// recorded as a payment to its rewards address, `NotRecorded` if every
    /// one was read and none is, else `Unreadable` (or `NotChecked`, with no
    /// EVM network). Each read as [`Self::kept_payment`] reads.
    #[cfg(feature = "native")]
    pub(crate) async fn quotes_recorded(
        &self,
        quotes: &[(QuoteHash, RewardsAddress, Amount)],
    ) -> KeptPayment {
        let Some(network) = self.evm_network.as_ref() else {
            return KeptPayment::NotChecked;
        };
        let chain = match read_back_chain(network) {
            Ok(chain) => chain,
            Err(error) => {
                tracing::warn!("cannot read the shared wave's payment records ({error})");
                return KeptPayment::Unreadable;
            }
        };
        let records = futures::future::join_all(
            quotes
                .iter()
                .map(|(hash, rewards, _)| records_payment_of(&chain, hash, rewards)),
        )
        .await;
        if records.contains(&Some(true)) {
            KeptPayment::Recorded
        } else if records.contains(&None) {
            KeptPayment::Unreadable
        } else {
            KeptPayment::NotRecorded
        }
    }

    /// Browser builds read no records back: the wallet callback owns the RPC.
    #[cfg(not(feature = "native"))]
    pub(crate) async fn kept_payment(&self, _proof: &[u8]) -> KeptPayment {
        KeptPayment::NotChecked
    }

    /// The root vault this client's root payments go to and its root proofs
    /// are read at: its root wallet's vault, else the root vault built in
    /// for its payment network ([`crate::config::root_vault_address`]).
    #[cfg(feature = "native")]
    #[must_use]
    pub(crate) fn root_vault(&self) -> Option<[u8; 20]> {
        if let Some(wallet) = self.root_wallet() {
            return Some(wallet.network().payment_vault_address().0 .0);
        }
        let network = self.evm_network.as_ref()?;
        crate::config::root_vault_address(network).map(|address| address.0 .0)
    }

    /// Whether the root vault `vault` records a wave under `key`, read
    /// through the payment network's RPC and those it falls back to, up to
    /// `reads` times 2 seconds apart while it reads empty or no RPC answers:
    /// `Recorded` once a record is read, `NotRecorded` if every read
    /// answered and none showed one, else `Unreadable` (`NotChecked` with
    /// no EVM network).
    #[cfg(feature = "native")]
    pub(crate) async fn root_wave_recorded(
        &self,
        vault: &[u8; 20],
        key: &[u8; 32],
        reads: usize,
    ) -> KeptPayment {
        const PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

        let Some(network) = self.evm_network.as_ref() else {
            return KeptPayment::NotChecked;
        };
        let chain = match read_back_chain(network) {
            Ok(chain) => chain,
            Err(error) => {
                tracing::warn!("cannot read the root vault's record ({error})");
                return KeptPayment::Unreadable;
            }
        };
        let mut answered = false;
        for read in 0..reads {
            if read > 0 {
                crate::runtime::sleep(PAUSE).await;
            }
            match chain.root_record(vault, key).await {
                Ok(Some(_)) => return KeptPayment::Recorded,
                Ok(None) => answered = true,
                Err(error) => {
                    tracing::debug!(
                        "reading the root vault's record under {} failed: {error}",
                        hex::encode(key)
                    );
                }
            }
        }
        if answered {
            KeptPayment::NotRecorded
        } else {
            KeptPayment::Unreadable
        }
    }

    /// The transaction that recorded the root vault `vault`'s wave under
    /// `key`, which a root wave's proofs and its envelope's payment record
    /// name: storers check an envelope's payment in the transactions its
    /// proof names. That is `own`, the payment's own transaction, when it
    /// was confirmed (`own_confirmed`) and its receipt holds the vault's
    /// `RootPaid` log naming the key. Otherwise another transaction recorded
    /// the same leaves first: `own` reverted or was replaced (by
    /// `replaced_by`, if that is known), or the vault found the wave already
    /// recorded and recorded nothing. That one is found by its `RootPaid`
    /// log, filtered by the key ([`recording_transaction_via`]).
    ///
    /// # Errors
    ///
    /// If the recording transaction can't be found or read: the payment's
    /// journal is kept, and a retry looks again, never paying again.
    #[cfg(feature = "native")]
    pub(crate) async fn root_wave_transaction(
        &self,
        vault: &[u8; 20],
        key: &[u8; 32],
        own: &[u8; 32],
        own_confirmed: bool,
        replaced_by: Option<&[u8; 32]>,
        earliest_quote: u64,
    ) -> crate::data::error::Result<[u8; 32]> {
        let network = self.evm_network.as_ref().ok_or_else(|| {
            Error::Payment("no EVM network to find the root wave's recording on".into())
        })?;
        let chain = read_back_chain(network)?;
        recording_transaction_via(
            &chain,
            &RootWave {
                vault,
                key,
                own,
                own_confirmed,
                replaced_by,
                earliest_quote,
            },
            ROOT_RECORDING_READS,
        )
        .await
    }
}

/// How many times the recording of a root wave is looked for, 2 seconds
/// apart, while its transaction's receipt or `RootPaid` log isn't found:
/// as many as the root vault's record is read after a payment, since an
/// RPC can lag the one that confirmed it.
#[cfg(feature = "native")]
const ROOT_RECORDING_READS: usize = 5;

/// A root wave whose recording transaction is looked for
/// ([`Client::root_wave_transaction`]).
#[cfg(feature = "native")]
pub(crate) struct RootWave<'a> {
    /// The root vault.
    pub(crate) vault: &'a [u8; 20],
    /// The wave's key.
    pub(crate) key: &'a [u8; 32],
    /// The payment's own transaction.
    pub(crate) own: &'a [u8; 32],
    /// Whether `own` was confirmed, rather than reverted or replaced.
    pub(crate) own_confirmed: bool,
    /// The transaction that took `own`'s nonce, if `own` was replaced.
    pub(crate) replaced_by: Option<&'a [u8; 32]>,
    /// The wave's earliest quote time, in Unix seconds.
    pub(crate) earliest_quote: u64,
}

/// [`Client::root_wave_transaction`], reading through `chain`, up to
/// `reads` times 2 seconds apart. The transaction that took the own one's
/// nonce, if it was replaced, is read first. Another transaction's
/// recording is searched for forwards from the block at the wave's earliest
/// quote time less [`ant_listings::CLOCK_MARGIN`] (a quote hash covers its
/// signed time, so the wave can't be recorded before its quotes, give or
/// take a node's clock against the chain's, and is recorded soon after
/// them) up to the block of `own`, where its receipt was read, else the
/// latest ([`ListingChain::root_paid_transaction`]). A search that used all
/// its calls before reaching its last block isn't made again: the error
/// says so, apart from finding nothing.
#[cfg(feature = "native")]
pub(crate) async fn recording_transaction_via(
    chain: &ListingChain,
    wave: &RootWave<'_>,
    reads: usize,
) -> crate::data::error::Result<[u8; 32]> {
    use super::listings::RootPaidSearch;
    const PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

    let RootWave {
        vault,
        key,
        own,
        own_confirmed,
        replaced_by,
        earliest_quote,
    } = *wave;
    let from_time = earliest_quote.saturating_sub(ant_listings::CLOCK_MARGIN);
    let mut until = None;
    let mut replacement_read = replaced_by.is_none();
    let mut problem = String::from("no RootPaid log names its key");
    for read in 0..reads {
        if read > 0 {
            crate::runtime::sleep(PAUSE).await;
        }
        if own_confirmed && until.is_none() {
            match chain.root_paid_in(own, vault, key).await {
                Ok(Some((true, _))) => return Ok(*own),
                Ok(Some((false, block))) => until = Some(block),
                Ok(None) => {
                    problem = "its own confirmed transaction's receipt isn't found".into();
                    continue;
                }
                Err(error) => {
                    problem = format!("its own transaction's receipt couldn't be read: {error}");
                    continue;
                }
            }
        }
        if let (Some(replacement), false) = (replaced_by, replacement_read) {
            match chain.root_paid_in(replacement, vault, key).await {
                Ok(Some((true, _))) => return Ok(*replacement),
                Ok(_) => replacement_read = true,
                Err(error) => {
                    problem = format!(
                        "the receipt of the transaction that replaced its own couldn't be read: \
                         {error}"
                    );
                    continue;
                }
            }
        }
        match chain
            .root_paid_transaction(vault, key, from_time, until)
            .await
        {
            Ok(RootPaidSearch::Found(recording)) => return Ok(recording),
            Ok(RootPaidSearch::NotFound) => problem = "no RootPaid log names its key".into(),
            Ok(RootPaidSearch::Incomplete { next, last }) => {
                problem = format!(
                    "the search for its RootPaid log stopped at its limit of eth_getLogs calls \
                     with blocks {next} to {last} unsearched, so it is incomplete, not empty"
                );
                break;
            }
            Err(error) => problem = format!("the search for its RootPaid log failed: {error}"),
        }
    }
    Err(Error::Payment(format!(
        "the transaction that recorded the root wave under its key {} wasn't found ({problem}); \
         its proofs and its envelope's payment record must name it. The payment's journal is \
         kept, and a retry looks for it again rather than pay twice. Don't delete the upload's \
         checkpoint",
        hex::encode(key)
    )))
}

/// The vault's record of `hash`, read up to 3 times 2 seconds apart while
/// no RPC answers; `None` if none did.
#[cfg(feature = "native")]
async fn read_record(chain: &ListingChain, hash: &QuoteHash) -> Option<VaultRecord> {
    /// Reads while no RPC answers, and the pause between them.
    const READS: usize = 3;
    const PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

    for read in 0..READS {
        if read > 0 {
            crate::runtime::sleep(PAUSE).await;
        }
        match chain.completed_payment(hash).await {
            Ok(record) => return Some(record),
            Err(error) => {
                tracing::debug!("reading the vault record of {hash:#x} failed: {error}");
            }
        }
    }
    None
}

/// Whether the vault's record of `hash` is a payment to `rewards`
/// ([`read_record`], [`records_payment_to`]); `None` if it couldn't be read.
#[cfg(feature = "native")]
async fn records_payment_of(
    chain: &ListingChain,
    hash: &QuoteHash,
    rewards: &RewardsAddress,
) -> Option<bool> {
    read_record(chain, hash)
        .await
        .map(|record| records_payment_to(&record, rewards))
}

/// Whether `record` is a payment to `rewards`: not empty, and to the first
/// 16 bytes of that address, as the vault records it.
#[cfg(feature = "native")]
fn records_payment_to(record: &VaultRecord, rewards: &RewardsAddress) -> bool {
    !record.amount.is_zero() && record.rewards_prefix[..] == rewards.as_slice()[..16]
}

/// What the vault holds for the payment a kept proof carries
/// ([`Client::kept_payment`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) enum KeptPayment {
    /// A payment to the paid quote's rewards address.
    Recorded,
    /// No payment, or another payment's record.
    NotRecorded,
    /// No RPC answered: the record is not paid again, and its proof is kept.
    Unreadable,
    /// Not read: a browser build, a client with no EVM network, or a proof
    /// that names no single paid quote. A kept proof is treated as when the
    /// record is unreadable: kept, and the record not paid again.
    NotChecked,
}

/// The reader [`Client::occupied_quotes`] reads paid quotes back through:
/// `network`'s RPC, then the RPCs it falls back to
/// ([`crate::config::fallback_rpc_urls`]).
#[cfg(feature = "native")]
fn read_back_chain(
    network: &ant_protocol::evm::Network,
) -> crate::data::error::Result<ListingChain> {
    ListingChain::new(network)
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

    /// The read-back reads through the payment network's RPC first, then
    /// every RPC the bundled network falls back to, in order: a provider
    /// that refuses a read doesn't stop it.
    #[cfg(feature = "native")]
    #[test]
    fn the_read_back_reads_through_the_rpc_fallback_list() {
        let bundled = crate::config::bundled_payment_network().unwrap();
        let fallbacks = crate::config::fallback_rpc_urls(&bundled);
        assert!(!fallbacks.is_empty());
        let mut expected = vec![bundled.rpc_url().to_string()];
        expected.extend(fallbacks);
        let chain = read_back_chain(&bundled).unwrap();
        assert_eq!(chain.rpc_urls(), expected.as_slice());
    }
    use crate::data::client::batch::SingleNodeQuotePayment;
    use ant_protocol::evm::PaymentQuote;
    use ant_protocol::payment::pricing::RecordWeight;
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
            payment: SingleNodeQuotePayment::from_quotes(quotes.clone(), RecordWeight::FULL)
                .unwrap(),
            peer_quotes: quotes
                .into_iter()
                .map(|q| (EncodedPeerId::new([q.rewards_address.0[0]; 32]), q))
                .collect(),
            commitment_sidecars: Vec::new(),
            vault: crate::data::client::root_payment::PaymentVault::V2,
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

/// What a payer outside the client paid, read back before anything is stored:
/// the finalize paths, `finalize_chunk` and `pointer_put_paid`, against a mock
/// vault RPC. The client's node was never started, so a refusal naming the
/// occupied quote was made before anything was sent, and a record stored
/// after an honest payment fails only for want of peers.
#[cfg(all(test, feature = "native"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod outside_payer_tests {
    use super::*;
    use crate::data::client::batch::{build_plan_proof, PaymentIntent, PreparedChunk};
    use crate::data::client::file::{
        ExternalPaymentInfo, FinalizeOutcome, FinalizeResume, PreparedUpload,
    };
    use crate::data::client::listings::test_chain::{serve, MockChain, VAULT};
    use ant_protocol::compute_address;
    use ant_protocol::evm::{Address, CustomNetwork, Network as EvmNetwork, PaymentQuote, TxHash};
    use ant_protocol::payment::pricing::RecordWeight;
    use ant_protocol::pointer::{Pointer, PointerTarget, PointerTargetKind};
    use bytes::Bytes;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    /// Where an occupier sends its dust.
    const STRANGER: [u8; 20] = [0xee; 20];

    /// Five quotes for `address`, priced 10 to 50, each node's rewards
    /// address and peer ID filled with its number; the median is paid 90.
    /// Signed at one fixed time, so the same chunk is quoted alike however
    /// often it is prepared, and its quote hashes match what was paid.
    fn plan_for(address: XorName, data_size: u64) -> ChunkPaymentPlan {
        let quotes: Vec<PaymentQuote> = (1..=5u8)
            .map(|seed| PaymentQuote {
                content: xor_name::XorName(address),
                timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
                price: Amount::from(10 * u64::from(seed)),
                rewards_address: RewardsAddress::new([seed; 20]),
                pub_key: vec![seed; 4],
                signature: vec![seed; 4],
                committed_key_count: 0,
                commitment_pin: None,
            })
            .collect();
        ChunkPaymentPlan {
            address,
            data_size,
            quoted_peers: Vec::new(),
            payment: SingleNodeQuotePayment::from_quotes(quotes.clone(), RecordWeight::FULL)
                .unwrap(),
            peer_quotes: quotes
                .into_iter()
                .map(|q| (EncodedPeerId::new([q.rewards_address.0[0]; 32]), q))
                .collect(),
            commitment_sidecars: Vec::new(),
            vault: crate::data::client::root_payment::PaymentVault::V2,
        }
    }

    /// A chunk of `byte` repeated, quoted and planned, not yet paid.
    fn prepared(byte: u8) -> PreparedChunk {
        let content = Bytes::from(vec![byte; 1024]);
        plan_for(compute_address(&content), 1024)
            .with_content(content)
            .unwrap()
    }

    /// The paid quote of `plan`: its hash, rewards address and amount.
    fn paid_of(plan: &ChunkPaymentPlan) -> (QuoteHash, RewardsAddress, Amount) {
        let q = plan
            .payment
            .quotes
            .iter()
            .find(|q| !q.amount.is_zero())
            .unwrap();
        (q.quote_hash, q.rewards_address, q.amount)
    }

    /// How the node that issued `plan`'s paid quote is named in an error.
    fn issuer_of(plan: &ChunkPaymentPlan) -> String {
        let (hash, _, _) = paid_of(plan);
        let (peer, _) = plan
            .peer_quotes
            .iter()
            .find(|(_, q)| q.hash() == hash)
            .unwrap();
        format!("node {}", hex::encode(peer.as_bytes()))
    }

    /// A transaction for every paid quote of `plans`, as an outside payer
    /// hands them back.
    fn transactions(plans: &[ChunkPaymentPlan]) -> HashMap<QuoteHash, TxHash> {
        plans
            .iter()
            .zip(1u8..)
            .map(|(plan, n)| (paid_of(plan).0, TxHash::from([n; 32])))
            .collect()
    }

    /// The vault's record of `plan`'s paid quote: the payment itself, or,
    /// `occupied`, a stranger's dust recorded first.
    fn vault_record(plan: &ChunkPaymentPlan, occupied: bool) -> (QuoteHash, VaultRecord) {
        let (hash, rewards, amount) = paid_of(plan);
        let (rewards, amount) = if occupied {
            (RewardsAddress::new(STRANGER), Amount::from(1u64))
        } else {
            (rewards, amount)
        };
        let mut rewards_prefix = [0u8; 16];
        rewards_prefix.copy_from_slice(&rewards.as_slice()[..16]);
        (
            hash,
            VaultRecord {
                rewards_prefix,
                amount,
            },
        )
    }

    /// A client of the vault behind a mock RPC that holds `records`, its
    /// node never started; and the network, kept for the client's life.
    async fn client_of(records: &[(QuoteHash, VaultRecord)]) -> (Client, crate::data::Network) {
        let mut chain = MockChain::default();
        for (hash, record) in records {
            chain
                .vault_records
                .insert(hash.0, (record.rewards_prefix, record.amount.to::<u128>()));
        }
        let url = serve(Arc::new(Mutex::new(chain))).await;
        let network = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(Arc::clone(network.node()), Default::default())
            .with_evm_network(EvmNetwork::Custom(CustomNetwork {
                rpc_url_http: url.parse().unwrap(),
                payment_token_address: Address::from([0x11; 20]),
                payment_vault_address: Address::from(VAULT),
            }));
        (client, network)
    }

    /// An upload of `chunks`, prepared for an outside payer.
    fn upload_of(chunks: Vec<PreparedChunk>) -> PreparedUpload {
        let total_chunks = chunks.len();
        let payment_intent = PaymentIntent::from_prepared_chunks(&chunks);
        PreparedUpload {
            data_map: self_encryption::DataMap::new(Vec::new()),
            payment_info: ExternalPaymentInfo::WaveBatch {
                prepared_chunks: chunks,
                payment_intent,
            },
            data_map_address: None,
            already_stored_addresses: Vec::new(),
            total_chunks,
            envelope: None,
        }
    }

    /// The errors name the node whose quote was occupied and say what became
    /// of the record: an upload quoted it again 3 times; a finalize or a
    /// pointer write can't quote it again.
    #[test]
    fn each_occupied_error_names_the_node_and_what_became_of_the_record() {
        let plan = plan_for([4; 32], 1024);
        let records = HashMap::from([vault_record(&plan, true)]);
        let occupied = occupied_in(std::slice::from_ref(&plan), &records);
        let messages = [
            occupied_error(&occupied).to_string(),
            occupied_at_finalize(&occupied).to_string(),
            occupied_pointer_proof(&occupied).to_string(),
        ];
        for message in &messages {
            assert!(message.contains(QUOTES_OCCUPIED), "{message}");
            assert!(message.contains(&issuer_of(&plan)), "{message}");
            assert!(message.contains(&hex::encode(&STRANGER[..16])), "{message}");
        }
        assert!(messages[0].contains("of 1 chunk(s)"), "{}", messages[0]);
        assert!(
            messages[0].contains("after 3 fresh quotes the chunk(s) are still unpaid"),
            "{}",
            messages[0]
        );
        assert!(messages[1].contains("of 1 chunk(s)"), "{}", messages[1]);
        assert!(
            messages[1].contains("a finalize can't quote them again")
                && !messages[1].contains("fresh quotes"),
            "{}",
            messages[1]
        );
        assert!(
            messages[2].contains("of 1 pointer state(s)"),
            "{}",
            messages[2]
        );
        assert!(
            messages[2].contains("prepare_pointer_payment"),
            "{}",
            messages[2]
        );
    }

    /// Only the chunks whose quote was occupied are set aside, each named
    /// with its own quote; the plans read back are what the chunks pay.
    #[test]
    fn only_occupied_chunks_are_set_aside() {
        let chunks = vec![prepared(1), prepared(2), prepared(3)];
        let plans = plans_of(&chunks);
        for (plan, chunk) in plans.iter().zip(&chunks) {
            assert_eq!(plan.address, chunk.address);
            assert_eq!(plan.data_size, chunk.content.len() as u64);
            assert_eq!(plan.peer_quotes.len(), chunk.peer_quotes.len());
        }
        assert_eq!(
            paid_quotes(&plans),
            PaymentIntent::from_prepared_chunks(&chunks)
                .payments
                .iter()
                .map(|(hash, _, _)| *hash)
                .collect::<Vec<_>>()
        );
        let records = HashMap::from([
            vault_record(&plans[0], false),
            vault_record(&plans[1], true),
        ]);
        let occupied = occupied_in(&plans, &records);
        let paid =
            crate::data::client::batch::finalize_batch_payment(chunks, &transactions(&plans))
                .unwrap();
        let (kept, unpaid) = set_aside_occupied(paid, &occupied);
        let kept: Vec<XorName> = kept.iter().map(|chunk| chunk.address).collect();
        assert_eq!(kept, vec![plans[0].address, plans[2].address]);
        assert_eq!(unpaid.len(), 1);
        assert_eq!(unpaid[0].0, plans[1].address);
        assert!(unpaid[0].1.contains(QUOTES_OCCUPIED), "{}", unpaid[0].1);
        assert!(
            unpaid[0].1.contains(&issuer_of(&plans[1])),
            "{}",
            unpaid[0].1
        );
    }

    /// A single-node proof plans back to the payment it carries; anything
    /// else is refused.
    #[test]
    fn a_proof_plans_back_to_the_payment_it_carries() {
        let plan = plan_for([5; 32], 2048);
        let proof = build_plan_proof(&plan, &transactions(std::slice::from_ref(&plan))).unwrap();
        let back = plan_of_proof(plan.address, 2048, RecordWeight::FULL, &proof).unwrap();
        let quotes = |plan: &ChunkPaymentPlan| {
            plan.payment
                .quotes
                .iter()
                .map(|q| (q.quote_hash, q.rewards_address, q.amount))
                .collect::<Vec<_>>()
        };
        assert_eq!(quotes(&back), quotes(&plan));
        assert_eq!(back.address, plan.address);
        assert_eq!(back.peer_quotes.len(), plan.peer_quotes.len());
        assert!(plan_of_proof(plan.address, 2048, RecordWeight::FULL, b"not a proof").is_err());
    }

    /// A proof planned back at a smaller weight expects the weighted amount,
    /// and a vault record of a full chunk's amount, which an earlier client
    /// pays for every record, is still the payment.
    #[test]
    fn a_proof_plans_back_at_its_weight() {
        use ant_protocol::payment::pricing::{record_weight, weighted_amount};
        use ant_protocol::pointer::{DATA_TYPE_POINTER, POINTER_WIRE_LEN};
        let plan = plan_for([6; 32], POINTER_WIRE_LEN as u64);
        let proof = build_plan_proof(&plan, &transactions(std::slice::from_ref(&plan))).unwrap();
        let weight = record_weight(DATA_TYPE_POINTER, POINTER_WIRE_LEN);
        let back = plan_of_proof(plan.address, POINTER_WIRE_LEN as u64, weight, &proof).unwrap();
        let paid = |plan: &ChunkPaymentPlan| {
            plan.payment
                .quotes
                .iter()
                .find(|q| !q.amount.is_zero())
                .map(|q| (q.quote_hash, q.rewards_address, q.price, q.amount))
                .unwrap()
        };
        let (hash, rewards, price, full) = paid(&plan);
        let (back_hash, back_rewards, _, weighted) = paid(&back);
        assert_eq!((back_hash, back_rewards), (hash, rewards));
        assert_eq!(full, price * Amount::from(3u64));
        assert_eq!(Some(weighted), weighted_amount(price, weight));
        assert!(weighted < full);
        let record = |amount| VaultRecord {
            rewards_prefix: rewards.as_slice()[..16].try_into().unwrap(),
            amount,
        };
        assert!(record(full).pays(&rewards, weighted));
        assert!(record(weighted).pays(&rewards, weighted));
        assert!(!record(weighted - Amount::from(1u64)).pays(&rewards, weighted));
    }

    /// `finalize_upload` sets the chunk whose quote was occupied aside before
    /// storing: it fails naming the node, is never sent, and the cost leaves
    /// its skipped payment out. The other chunk goes on to the store, which
    /// fails here for want of peers.
    #[tokio::test]
    async fn finalize_upload_sets_an_occupied_chunk_aside() {
        let plans = plans_of(&[prepared(1), prepared(2)]);
        let (client, _network) = client_of(&[
            vault_record(&plans[0], true),
            vault_record(&plans[1], false),
        ])
        .await;
        let error = client
            .finalize_upload(
                upload_of(vec![prepared(1), prepared(2)]),
                &transactions(&plans),
            )
            .await
            .expect_err("an occupied chunk can't complete the upload");
        let Error::PartialUpload {
            stored,
            failed,
            spend,
            reason,
            ..
        } = error
        else {
            panic!("expected a partial upload, got {error}");
        };
        assert!(stored.is_empty());
        assert_eq!(failed.len(), 2);
        assert_eq!(
            failed[0].0, plans[0].address,
            "the occupied chunk comes first"
        );
        assert!(failed[0].1.contains(QUOTES_OCCUPIED), "{}", failed[0].1);
        assert!(
            failed[0].1.contains(&issuer_of(&plans[0])),
            "{}",
            failed[0].1
        );
        assert_eq!(failed[1].0, plans[1].address);
        assert!(!failed[1].1.contains(QUOTES_OCCUPIED), "{}", failed[1].1);
        assert_eq!(spend.storage_cost_atto, paid_of(&plans[1]).2.to_string());
        assert!(reason.starts_with("finalize_upload: "), "{reason}");
        assert!(reason.contains(QUOTES_OCCUPIED), "{reason}");
    }

    /// The resumable finalize does the same and leaves the occupied chunk out
    /// of the resume handle, which lists it; a resume reports it failed
    /// again and never completes the upload.
    #[tokio::test]
    async fn the_resumable_finalize_keeps_an_occupied_chunk_out_of_the_handle() {
        let plans = plans_of(&[prepared(1), prepared(2)]);
        let (client, _network) = client_of(&[
            vault_record(&plans[0], true),
            vault_record(&plans[1], false),
        ])
        .await;
        let outcome = client
            .finalize_upload_resumable(
                upload_of(vec![prepared(1), prepared(2)]),
                &transactions(&plans),
            )
            .await
            .unwrap();
        let FinalizeOutcome::Partial { result, resume } = outcome else {
            panic!("an occupied chunk can't complete the upload");
        };
        assert_eq!(result.chunks_stored, 0);
        assert_eq!(result.chunks_failed, 2);
        assert_eq!(result.storage_cost_atto, paid_of(&plans[1]).2.to_string());
        let FinalizeResume::Wave(handle) = &resume else {
            panic!("expected a wave handle");
        };
        assert_eq!(handle.occupied().len(), 1);
        assert_eq!(handle.occupied()[0].0, plans[0].address);
        let shown = format!("{handle:?}");
        assert!(
            shown.contains("unstored: 1") && shown.contains("occupied: 1"),
            "{shown}"
        );

        let FinalizeOutcome::Partial { result, resume } =
            client.finalize_resume(resume).await.unwrap()
        else {
            panic!("a resume can't complete it either");
        };
        assert_eq!(result.chunks_failed, 2);
        let FinalizeResume::Wave(handle) = &resume else {
            panic!("expected a wave handle");
        };
        assert_eq!(handle.occupied()[0].0, plans[0].address);
    }

    /// `finalize_chunk` refuses an occupied chunk before sending it; an
    /// honest payment goes on to the store.
    #[tokio::test]
    async fn finalize_chunk_refuses_an_occupied_chunk_before_sending() {
        let plans = plans_of(&[prepared(1), prepared(2)]);
        let (client, _network) = client_of(&[
            vault_record(&plans[0], true),
            vault_record(&plans[1], false),
        ])
        .await;
        let refused = client
            .finalize_chunk(prepared(1), &transactions(&plans[..1]))
            .await
            .expect_err("occupied");
        let text = refused.to_string();
        assert!(matches!(refused, Error::Payment(_)), "{text}");
        assert!(text.contains(QUOTES_OCCUPIED), "{text}");
        assert!(text.contains(&issuer_of(&plans[0])), "{text}");
        assert!(text.contains("a finalize can't quote them again"), "{text}");
        let stored = client
            .finalize_chunk(prepared(2), &transactions(&plans[1..]))
            .await
            .expect_err("no peers to store on");
        assert!(!stored.to_string().contains(QUOTES_OCCUPIED), "{stored}");
    }

    /// `pointer_put_paid` reads the proof's paid quote back and refuses an
    /// occupied one before sending the state; an honest proof goes on to the
    /// write, and a proof that isn't a single-node proof is refused.
    #[tokio::test]
    async fn pointer_put_paid_refuses_an_occupied_proof_before_sending() {
        let (owner, secret) =
            ant_protocol::pqc::api::ml_dsa_65().generate_keypair_from_seed(&[9; 32]);
        let first = Pointer::create(
            &secret,
            &owner,
            PointerTarget::new(PointerTargetKind::Chunk, [1; 32]),
        )
        .unwrap();
        let second = first
            .update(
                &secret,
                PointerTarget::new(PointerTargetKind::Chunk, [2; 32]),
            )
            .unwrap();
        let size = ant_protocol::pointer::POINTER_WIRE_LEN as u64;
        let plans = [
            plan_for(first.state_id(), size),
            plan_for(second.state_id(), size),
        ];
        let (client, _network) = client_of(&[
            vault_record(&plans[0], true),
            vault_record(&plans[1], false),
        ])
        .await;
        let proof = |plan: &ChunkPaymentPlan| {
            build_plan_proof(plan, &transactions(std::slice::from_ref(plan))).unwrap()
        };

        let refused = client
            .pointer_put_paid(&first, proof(&plans[0]))
            .await
            .expect_err("occupied");
        let text = refused.to_string();
        assert!(text.contains(QUOTES_OCCUPIED), "{text}");
        assert!(text.contains("of 1 pointer state(s)"), "{text}");
        assert!(text.contains(&issuer_of(&plans[0])), "{text}");

        let written = client
            .pointer_put_paid(&second, proof(&plans[1]))
            .await
            .expect_err("no peers to write to");
        assert!(!written.to_string().contains(QUOTES_OCCUPIED), "{written}");

        let garbage = client
            .pointer_put_paid(&second, b"not a proof".to_vec())
            .await
            .expect_err("unreadable proof");
        assert!(
            garbage
                .to_string()
                .contains("cannot read the pointer's payment proof"),
            "{garbage}"
        );
    }
}
