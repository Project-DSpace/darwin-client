//! Occupied quotes, against the DARWIN vault's code on Anvil, which the
//! shared network runs.
//!
//! The DARWIN vault keeps a quote hash's first non-zero payment and skips
//! later ones without reverting. Someone who knows a quote hash before it is
//! paid (realistically the node that issued it) can record it first with a
//! dust payment to an address of its own. These tests play that node: each
//! payment's first quote is recorded with 1 atto to a stranger's address just
//! before the upload pays it, or, for a payer outside the client, just before
//! that payer pays.

use crate::support::runner::Case;
use crate::support::MiniTestnet;
use ant_core::data::client::upload::{UploadAdapter, UploadPayment, UploadRecord};
use ant_core::data::client::upload_state::UploadState;
use ant_core::data::{
    compute_address, ChunkPaymentPlan, Error, ExternalPaymentInfo, FinalizeOutcome, FinalizeResume,
    PaymentMode, SingleNodeQuotePayment, MAX_OCCUPIED_REQUOTES, QUOTES_OCCUPIED,
};
use ant_protocol::evm::contract::payment_vault::interface::IPaymentVault;
use ant_protocol::evm::utils::http_provider;
use ant_protocol::evm::{
    Amount, EncodedPeerId, PaymentQuote, QuoteHash, RewardsAddress, TxHash, Wallet,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network(
            "occupied::an_occupied_quote_is_quoted_and_paid_again",
            an_occupied_quote_is_quoted_and_paid_again,
        ),
        Case::on_network(
            "occupied::a_chunk_whose_quotes_keep_being_occupied_names_the_node",
            a_chunk_whose_quotes_keep_being_occupied_names_the_node,
        ),
        Case::on_network(
            "occupied::an_outside_payers_occupied_quote_is_set_aside_at_finalize",
            an_outside_payers_occupied_quote_is_set_aside_at_finalize,
        ),
    ]
}

/// Where the occupier sends its dust.
const STRANGER: [u8; 20] = [0xee; 20];

/// One payment the upload asked for: the quotes it paid, and the one the
/// occupier recorded first with the node that issued it, if any.
struct Asked {
    quotes: Vec<(QuoteHash, [u8; 32])>,
    occupied: Option<(QuoteHash, EncodedPeerId)>,
}

/// Records staged in memory, paid by a wallet. Before each of the first
/// `occupy` payments, the occupier records that payment's first quote.
struct Occupier<'a> {
    chunks: Vec<Bytes>,
    wallet: &'a Wallet,
    occupy: usize,
    asked: Mutex<Vec<Asked>>,
}

impl<'a> Occupier<'a> {
    fn new(count: usize, wallet: &'a Wallet, occupy: usize) -> Self {
        let chunks = (0..count)
            .map(|_| Bytes::from((0..2_000).map(|_| rand::random::<u8>()).collect::<Vec<_>>()))
            .collect();
        Self {
            chunks,
            wallet,
            occupy,
            asked: Mutex::new(Vec::new()),
        }
    }

    fn records(&self) -> Vec<UploadRecord> {
        self.chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| UploadRecord {
                address: compute_address(chunk),
                size: chunk.len() as u64,
                index,
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl UploadAdapter for Occupier<'_> {
    async fn load(&self, record: UploadRecord) -> ant_core::data::Result<Bytes> {
        Ok(self.chunks[record.index].clone())
    }

    async fn pay(&self, plans: &[ChunkPaymentPlan]) -> ant_core::data::Result<UploadPayment> {
        let mut quotes = Vec::new();
        let mut payments = Vec::new();
        for plan in plans {
            for q in plan.payment.quotes.iter().filter(|q| !q.amount.is_zero()) {
                quotes.push((q.quote_hash, plan.address));
                payments.push((q.quote_hash, q.rewards_address, q.amount));
            }
        }
        let call = self.asked.lock().unwrap().len();
        let occupied = if call < self.occupy {
            let (hash, address) = quotes[0];
            let plan = plans.iter().find(|p| p.address == address).unwrap();
            let issuer = plan
                .peer_quotes
                .iter()
                .find(|(_, q)| q.hash() == hash)
                .map(|(peer, _)| peer.clone())
                .unwrap();
            self.wallet
                .pay_for_quotes([(hash, RewardsAddress::new(STRANGER), Amount::from(1u64))])
                .await
                .map_err(|e| Error::Payment(e.0.to_string()))?;
            Some((hash, issuer))
        } else {
            None
        };
        self.asked.lock().unwrap().push(Asked { quotes, occupied });
        let (transactions, gas) = self
            .wallet
            .pay_for_quotes(payments)
            .await
            .map_err(|e| Error::Payment(e.0.to_string()))?;
        let amount = plans
            .iter()
            .fold(Amount::ZERO, |sum, plan| sum + plan.payment.total_amount());
        Ok(UploadPayment {
            transactions: transactions.into_iter().collect(),
            amount,
            gas: gas.gas_cost_wei,
            root: None,
        })
    }
}

/// The vault's record for `hash`: the first 16 bytes of its rewards address,
/// and its amount.
async fn record(testnet: &MiniTestnet, hash: QuoteHash) -> ([u8; 16], u128) {
    let network = testnet.evm_network();
    let vault = IPaymentVault::new(
        *network.payment_vault_address(),
        http_provider(network.rpc_url().clone()),
    );
    let record = vault
        .completedPayments(hash)
        .call()
        .await
        .expect("read record");
    (record.rewardsAddress.0, record.amount)
}

async fn an_occupied_quote_is_quoted_and_paid_again(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();
    let staged = Occupier::new(3, testnet.wallet(), 1);
    let before = testnet.wallet().balance_of_tokens().await.unwrap();

    let outcome = client
        .upload_records(
            staged.records(),
            &mut UploadState::default(),
            &staged,
            PaymentMode::Single,
        )
        .await
        .expect("upload");

    // Every chunk is stored and reads back.
    for chunk in &staged.chunks {
        let address = compute_address(chunk);
        assert!(outcome.addresses.contains(&address));
        let stored = client.chunk_get(&address).await.expect("fetch");
        assert_eq!(stored.expect("stored").content, *chunk);
    }

    let asked = std::mem::take(&mut *staged.asked.lock().unwrap());
    assert_eq!(
        asked.len(),
        2,
        "one payment, then one for the occupied chunk"
    );
    let (occupied, _) = asked[0].occupied.clone().expect("first payment occupied");
    let occupied_chunk = asked[0]
        .quotes
        .iter()
        .find(|(hash, _)| *hash == occupied)
        .unwrap()
        .1;
    // The second payment is a fresh quote for that chunk alone.
    assert_eq!(asked[1].quotes.len(), 1);
    let (fresh, chunk) = asked[1].quotes[0];
    assert_eq!(chunk, occupied_chunk);
    assert_ne!(fresh, occupied);

    // The occupied record stays the occupier's; the fresh one is ours.
    assert_eq!(
        record(&testnet, occupied).await,
        (STRANGER[..16].try_into().unwrap(), 1)
    );
    assert_ne!(record(&testnet, fresh).await.1, 0);

    // The skipped payment moved nothing: the wallet paid what the upload
    // reports, plus the occupier's 1 atto (it is the same wallet here).
    let after = testnet.wallet().balance_of_tokens().await.unwrap();
    assert_eq!(before - after, outcome.amount + Amount::from(1u64));
}

async fn a_chunk_whose_quotes_keep_being_occupied_names_the_node(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();
    let staged = Occupier::new(3, testnet.wallet(), usize::MAX);

    let error = client
        .upload_records(
            staged.records(),
            &mut UploadState::default(),
            &staged,
            PaymentMode::Single,
        )
        .await
        .expect_err("a chunk stays unpaid");

    let asked = std::mem::take(&mut *staged.asked.lock().unwrap());
    assert_eq!(asked.len(), MAX_OCCUPIED_REQUOTES + 1);
    let (_, issuer) = asked.last().unwrap().occupied.clone().unwrap();
    let occupied_chunk = asked.last().unwrap().quotes[0].1;
    // The other chunks were paid once and stored; the occupied one failed,
    // and the reason names the node whose quotes were occupied.
    let Error::PartialUpload { stored, failed, .. } = error else {
        panic!("expected a partial upload, got {error}");
    };
    assert_eq!(stored.len(), 2);
    assert!(!stored.contains(&occupied_chunk));
    assert_eq!(failed.len(), 1);
    let (chunk, reason) = &failed[0];
    assert_eq!(*chunk, occupied_chunk);
    assert!(reason.contains(QUOTES_OCCUPIED), "{reason}");
    assert!(
        reason.contains(&format!("node {}", hex::encode(issuer.as_bytes()))),
        "{reason}"
    );
}

/// Record `hash`'s payment first, with 1 atto to the stranger, as the node
/// that issued the quote could.
async fn occupy(wallet: &Wallet, hash: QuoteHash) {
    wallet
        .pay_for_quotes([(hash, RewardsAddress::new(STRANGER), Amount::from(1u64))])
        .await
        .expect("occupy the quote");
}

/// The paid quote of a payment: its hash, the node that issued it, and the
/// amount.
fn paid_quote(
    payment: &SingleNodeQuotePayment,
    peer_quotes: &[(EncodedPeerId, PaymentQuote)],
) -> (QuoteHash, EncodedPeerId, Amount) {
    let paid = payment
        .quotes
        .iter()
        .find(|quote| !quote.amount.is_zero())
        .expect("a paid quote");
    let issuer = peer_quotes
        .iter()
        .find(|(_, quote)| quote.hash() == paid.quote_hash)
        .map(|(peer, _)| peer.clone())
        .expect("its issuer");
    (paid.quote_hash, issuer, paid.amount)
}

/// Pay `payments` as a payer outside the client does, returning the
/// transaction of each quote.
async fn pay_outside(
    wallet: &Wallet,
    payments: Vec<(QuoteHash, RewardsAddress, Amount)>,
) -> HashMap<QuoteHash, TxHash> {
    let (transactions, _) = wallet.pay_for_quotes(payments).await.expect("pay");
    transactions.into_iter().collect()
}

/// A payer outside the client pays an upload whose content chunk's quote
/// was occupied just before. `finalize_upload` and the resumable finalize
/// read every paid quote back before storing: the occupied chunk is never
/// sent and fails naming the node that issued its quote, the other chunks
/// are stored, the envelope is held back, and the cost leaves the skipped
/// payment out. The resume handle leaves the chunk out, so a resume never
/// completes the upload.
async fn an_outside_payers_occupied_quote_is_set_aside_at_finalize(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();
    for resumable in [false, true] {
        let content: Vec<u8> = (0..20_000).map(|_| rand::random::<u8>()).collect();
        let prepared = client
            .data_prepare_upload(Bytes::from(content))
            .await
            .expect("prepare");
        let envelope = prepared.envelope.as_ref().expect("an envelope").address();
        let ExternalPaymentInfo::WaveBatch {
            prepared_chunks,
            payment_intent,
        } = &prepared.payment_info
        else {
            panic!("expected a wave batch");
        };
        let chunk = prepared_chunks
            .iter()
            .find(|chunk| chunk.address != envelope)
            .expect("a content chunk");
        let others: Vec<[u8; 32]> = prepared_chunks
            .iter()
            .map(|other| other.address)
            .filter(|address| *address != chunk.address && *address != envelope)
            .collect();
        let occupied_chunk = chunk.address;
        let (hash, issuer, skipped) = paid_quote(&chunk.payment, &chunk.peer_quotes);
        let total = payment_intent.total_amount;
        occupy(testnet.wallet(), hash).await;
        let transactions = pay_outside(testnet.wallet(), payment_intent.payments.clone()).await;
        let named = |reason: &str| {
            reason.contains(QUOTES_OCCUPIED)
                && reason.contains(&format!("node {}", hex::encode(issuer.as_bytes())))
        };

        if resumable {
            let outcome = client
                .finalize_upload_resumable(prepared, &transactions)
                .await
                .expect("finalize");
            let FinalizeOutcome::Partial { result, resume } = outcome else {
                panic!("an occupied chunk can't complete the upload");
            };
            assert_eq!(result.chunks_stored, others.len());
            assert_eq!(
                result.chunks_failed, 2,
                "the occupied chunk and the envelope"
            );
            assert_eq!(result.storage_cost_atto, (total - skipped).to_string());
            let FinalizeResume::Wave(handle) = &resume else {
                panic!("expected a wave handle");
            };
            assert_eq!(handle.occupied().len(), 1);
            assert_eq!(handle.occupied()[0].0, occupied_chunk);
            assert!(named(&handle.occupied()[0].1), "{}", handle.occupied()[0].1);
            let FinalizeOutcome::Partial { result, .. } =
                client.finalize_resume(resume).await.expect("resume")
            else {
                panic!("a resume can't complete it either");
            };
            assert_eq!(result.chunks_failed, 2);
        } else {
            let error = client
                .finalize_upload(prepared, &transactions)
                .await
                .expect_err("an occupied chunk can't complete the upload");
            let Error::PartialUpload {
                mut stored,
                failed,
                spend,
                ..
            } = error
            else {
                panic!("expected a partial upload, got {error}");
            };
            stored.sort_unstable();
            let mut expected = others.clone();
            expected.sort_unstable();
            assert_eq!(stored, expected, "every other chunk is stored");
            assert_eq!(failed.len(), 2);
            assert_eq!(failed[0].0, occupied_chunk);
            assert!(named(&failed[0].1), "{}", failed[0].1);
            assert_eq!(failed[1].0, envelope, "the envelope is held back");
            assert_eq!(spend.storage_cost_atto, (total - skipped).to_string());
        }

        for address in &others {
            assert!(client.chunk_get(address).await.expect("fetch").is_some());
        }
        assert!(client
            .chunk_get(&occupied_chunk)
            .await
            .expect("fetch")
            .is_none());
        assert!(client.chunk_get(&envelope).await.expect("fetch").is_none());
        assert_eq!(
            record(&testnet, hash).await,
            (STRANGER[..16].try_into().unwrap(), 1)
        );
    }
}
