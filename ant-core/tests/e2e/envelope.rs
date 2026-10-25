//! E2E tests for uploads with an envelope: the envelope is paid in the same
//! payment as the content, stored with it, and its proof record checks out
//! against the chain.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use ant_core::ant_listings::{
    Envelope, Metadata, PaymentField, ShownFields, DATA_PAYMENT_MADE_TOPIC,
};
use ant_core::data::client::adaptive::{AdaptiveConfig, ChannelMax};
use ant_core::data::client::upload::{
    MerkleUploadPayment, UploadAdapter, UploadPayment, UploadRecord,
};
use ant_core::data::client::upload_state::UploadState;
use ant_core::data::{
    compute_address, forget_upload_record, proof_data_map, ChunkPaymentPlan, Client,
    EnvelopeOptions, Error, ListingChain, PaymentMode, PreparedMerkleBatch, UploadPayer,
    Visibility,
};
use ant_protocol::evm::{Amount, Wallet};
use bytes::Bytes;
use serial_test::serial;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use support::{
    assert_batch_refused, test_client_config, wallet_spend, MiniTestnet, DEFAULT_NODE_COUNT,
    MERKLE_TESTNET_NODES, MERKLE_TESTNET_QUOTE_CONCURRENCY,
};
use tempfile::{NamedTempFile, TempDir};

async fn setup() -> (Client, MiniTestnet) {
    let testnet = MiniTestnet::start(DEFAULT_NODE_COUNT).await;
    let node = testnet.node(3).expect("Node 3 should exist");
    let client = Client::from_node(Arc::clone(&node), test_client_config())
        .with_wallet(testnet.wallet().clone());
    (client, testnet)
}

fn input(byte: u8) -> (NamedTempFile, Vec<u8>) {
    let mut file = NamedTempFile::new().expect("create temp file");
    let data: Vec<u8> = (0..20_000u32).map(|i| byte ^ (i % 251) as u8).collect();
    file.write_all(&data).expect("write temp file");
    file.flush().expect("flush temp file");
    (file, data)
}

/// How many vault payments the transaction `tx_hash` made.
async fn payments_in(chain: &ListingChain, tx_hash: &[u8; 32]) -> usize {
    let (receipt, _) = chain
        .transaction(tx_hash)
        .await
        .expect("chain answers")
        .expect("transaction on chain");
    receipt
        .logs
        .iter()
        .filter(|log| log.topics.first() == Some(&DATA_PAYMENT_MADE_TOPIC))
        .count()
}

/// One per-chunk payment: the addresses it paid and its transactions.
type PaidWave = (Vec<[u8; 32]>, Vec<[u8; 32]>);

/// Records staged in memory and paid by a wallet, for driving the upload
/// engine directly. Once anything is paid, the record at `corrupt` loads with
/// other bytes, so it fails to store.
struct StagedRecords<'a> {
    chunks: Vec<Bytes>,
    wallet: &'a Wallet,
    corrupt: Option<usize>,
    paid: AtomicBool,
    /// Each per-chunk payment.
    payments: Mutex<Vec<PaidWave>>,
    /// Merkle batches the engine asked this payer to pay.
    merkle_payments: AtomicUsize,
}

impl<'a> StagedRecords<'a> {
    fn new(chunks: Vec<Bytes>, wallet: &'a Wallet, corrupt: Option<usize>) -> Self {
        Self {
            chunks,
            wallet,
            corrupt,
            paid: AtomicBool::new(false),
            payments: Mutex::new(Vec::new()),
            merkle_payments: AtomicUsize::new(0),
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
impl UploadAdapter for StagedRecords<'_> {
    async fn load(&self, record: UploadRecord) -> ant_core::data::Result<Bytes> {
        let bytes = self.chunks[record.index].clone();
        if self.paid.load(Ordering::SeqCst) && self.corrupt == Some(record.index) {
            let mut changed = bytes.to_vec();
            changed[0] ^= 0xff;
            return Ok(Bytes::from(changed));
        }
        Ok(bytes)
    }

    async fn pay(&self, plans: &[ChunkPaymentPlan]) -> ant_core::data::Result<UploadPayment> {
        let payments = plans
            .iter()
            .flat_map(|plan| {
                plan.payment
                    .quotes
                    .iter()
                    .map(|q| (q.quote_hash, q.rewards_address, q.amount))
            })
            .collect::<Vec<_>>();
        let (transactions, gas) = self
            .wallet
            .pay_for_quotes(payments)
            .await
            .map_err(|e| Error::Payment(e.0.to_string()))?;
        self.paid.store(true, Ordering::SeqCst);
        // One entry per quote paid; the distinct transactions.
        let mut tx_hashes: Vec<[u8; 32]> = transactions.values().map(|tx| tx.0).collect();
        tx_hashes.sort_unstable();
        tx_hashes.dedup();
        self.payments
            .lock()
            .unwrap()
            .push((plans.iter().map(|plan| plan.address).collect(), tx_hashes));
        let amount = plans
            .iter()
            .fold(Amount::ZERO, |sum, plan| sum + plan.payment.total_amount());
        Ok(UploadPayment {
            transactions: transactions.into_iter().collect(),
            amount,
            gas: gas.gas_cost_wei,
        })
    }

    async fn pay_merkle(
        &self,
        batch: &PreparedMerkleBatch,
    ) -> ant_core::data::Result<MerkleUploadPayment> {
        self.merkle_payments.fetch_add(1, Ordering::SeqCst);
        let (winner_pool, amount, gas) = self
            .wallet
            .pay_for_merkle_tree(
                batch.depth,
                batch.pool_commitments.clone(),
                batch.merkle_payment_timestamp,
            )
            .await
            .map_err(|e| Error::Payment(e.to_string()))?;
        self.paid.store(true, Ordering::SeqCst);
        Ok(MerkleUploadPayment {
            winner_pool,
            amount,
            gas: gas.gas_cost_wei,
        })
    }
}

/// Pays with a wallet on behalf of `account`: one of the accounts of a
/// payer serving several, as a gateway does.
struct AccountPayer<'a> {
    wallet: &'a Wallet,
    account: &'static str,
}

#[async_trait::async_trait]
impl UploadPayer for AccountPayer<'_> {
    async fn pay_quotes(
        &self,
        plans: &[ChunkPaymentPlan],
    ) -> ant_core::data::Result<UploadPayment> {
        let payments = plans
            .iter()
            .flat_map(|plan| {
                plan.payment
                    .quotes
                    .iter()
                    .map(|q| (q.quote_hash, q.rewards_address, q.amount))
            })
            .collect::<Vec<_>>();
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
        })
    }

    async fn pay_merkle(
        &self,
        _batch: &PreparedMerkleBatch,
    ) -> ant_core::data::Result<MerkleUploadPayment> {
        Err(Error::Payment("not used here".into()))
    }

    fn checkpoint_scope(&self) -> Vec<u8> {
        self.account.as_bytes().to_vec()
    }
}

/// `count` chunks of random bytes, and a private envelope after them.
fn content_and_envelope(count: usize, size: usize) -> (Vec<Bytes>, [u8; 32]) {
    let mut chunks: Vec<Bytes> = (0..count)
        .map(|_| Bytes::from((0..size).map(|_| rand::random::<u8>()).collect::<Vec<_>>()))
        .collect();
    let (map, _) = ant_core::ant_listings::self_encryption::encrypt(Bytes::from(vec![1u8; 4_000]))
        .expect("encrypt");
    let envelope = Envelope::withheld(
        &map,
        &rand::random(),
        Metadata::default(),
        ShownFields::ALL,
        false,
    )
    .expect("envelope");
    chunks.push(Bytes::from(envelope.to_bytes()));
    (chunks, envelope.address())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn the_envelope_is_never_sent_when_content_fails_to_store() {
    let (client, testnet) = setup().await;
    let (chunks, envelope) = content_and_envelope(4, 2_000);
    // The second content record fails to store after payment.
    let staged = StagedRecords::new(chunks, testnet.wallet(), Some(1));
    let mut records = staged.records();
    let last = records.pop().expect("the envelope");
    let mut state = UploadState::default();
    let error = client
        .upload_records_then(records, last, &mut state, &staged, PaymentMode::Single)
        .await
        .expect_err("a content record fails");
    let Error::PartialUpload { stored, failed, .. } = error else {
        panic!("expected a partial upload, got {error}");
    };
    // The envelope was paid with the content, then held back: reported
    // failed with its payment kept, and never sent.
    let paid: Vec<[u8; 32]> = staged
        .payments
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(addresses, _)| addresses.clone())
        .collect();
    assert!(paid.contains(&envelope));
    assert!(!stored.contains(&envelope));
    assert!(
        failed.iter().any(|(address, why)| *address == envelope
            && why == "not stored, since other records failed to store"),
        "{failed:?}"
    );
    assert!(client.chunk_get(&envelope).await.expect("fetch").is_none());

    drop(client);
    testnet.teardown().await;
}

/// A testnet large enough that a client asks its nodes for merkle
/// candidates, and a client on it, set up as for the batch payments the
/// tests below attempt. The client quotes at most
/// [`MERKLE_TESTNET_QUOTE_CONCURRENCY`] records at a time, so that it can pay
/// a 64-record wave per chunk on this testnet ([`MERKLE_TESTNET_NODES`]
/// says why).
async fn setup_merkle_sized() -> (Client, MiniTestnet) {
    let testnet = MiniTestnet::start(MERKLE_TESTNET_NODES).await;
    let node = testnet.node(5).expect("Node 5 should exist");
    let config = ant_core::data::ClientConfig {
        quote_timeout_secs: 120,
        store_timeout_secs: 120,
        close_group_size: 20,
        adaptive: AdaptiveConfig {
            max: ChannelMax {
                quote: MERKLE_TESTNET_QUOTE_CONCURRENCY,
                ..ChannelMax::default()
            },
            ..AdaptiveConfig::default()
        },
        ..Default::default()
    };
    let client = Client::from_node(Arc::clone(&node), config).with_wallet(testnet.wallet().clone());
    (client, testnet)
}

/// From 33 content records the upload engine would pay a merkle batch of 32,
/// then the last content record with the envelope per chunk. darwin-node
/// refuses the batch at quote time, so the payer is asked for nothing,
/// neither the batch nor the per-chunk payment after it, and the envelope is
/// never sent. This test doesn't reach the envelope's per-chunk payment after
/// a paid batch: the split is pinned in `merkle_unit.rs`, and the envelope's
/// place after the batches (the final per-chunk wave, stored last) in
/// `src/data/client/upload.rs`'s unit tests (`PerChunkWaves`).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn from_33_content_records_a_merkle_batch_is_refused_and_nothing_is_paid() {
    let (client, testnet) = setup_merkle_sized().await;
    let (chunks, envelope) = content_and_envelope(33, 1_024);
    let staged = StagedRecords::new(chunks, testnet.wallet(), None);
    let mut records = staged.records();
    let last = records.pop().expect("the envelope");
    let mut state = UploadState::default();
    let before = wallet_spend(testnet.wallet()).await;
    let error = client
        .upload_records_then(records, last, &mut state, &staged, PaymentMode::Merkle)
        .await
        .expect_err("darwin-node refuses batch payments");
    assert_batch_refused(&error);

    assert_eq!(staged.merkle_payments.load(Ordering::SeqCst), 0);
    assert!(staged.payments.lock().unwrap().is_empty());
    assert!(!staged.paid.load(Ordering::SeqCst));
    assert_eq!(wallet_spend(testnet.wallet()).await, before);
    assert!(client.chunk_get(&envelope).await.expect("fetch").is_none());

    drop(client);
    testnet.teardown().await;
}

/// From 65 content records, at the merkle threshold, `PaymentMode::Auto` asks
/// the nodes for a batch's candidates; darwin-node refuses them, so every
/// record is paid per chunk instead, and the envelope joins the last
/// per-chunk payment after the content: the first payment is 64 content
/// records, the second the last one and the envelope, in one transaction.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn from_65_content_records_auto_pays_per_chunk_and_the_envelope_joins_the_last_payment() {
    let (client, testnet) = setup_merkle_sized().await;
    let chain = ListingChain::new(testnet.evm_network()).expect("chain reader");
    let (chunks, envelope) = content_and_envelope(65, 1_024);
    let envelope_bytes = chunks.last().cloned().expect("the envelope");
    let staged = StagedRecords::new(chunks, testnet.wallet(), None);
    let mut records = staged.records();
    let last = records.pop().expect("the envelope");
    let content: Vec<[u8; 32]> = records.iter().map(|record| record.address).collect();
    let mut state = UploadState::default();
    let outcome = client
        .upload_records_then(records, last, &mut state, &staged, PaymentMode::Auto)
        .await
        .expect("upload");
    assert_eq!(outcome.mode, PaymentMode::Single);
    assert_eq!(outcome.addresses.len(), 66);
    assert_eq!(outcome.addresses.last(), Some(&envelope));
    assert_eq!(staged.merkle_payments.load(Ordering::SeqCst), 0);

    let payments = staged.payments.lock().unwrap().clone();
    assert_eq!(payments.len(), 2, "{payments:?}");
    let (first, _) = &payments[0];
    assert_eq!(first.len(), 64);
    assert!(!first.contains(&envelope));
    let (second, transactions) = &payments[1];
    assert_eq!(second.len(), 2);
    assert!(second.contains(&envelope));
    assert!(second.contains(&content[64]));
    assert_eq!(transactions.len(), 1);
    assert_eq!(payments_in(&chain, &transactions[0]).await, 2);

    // The envelope reads back.
    let chunk = client
        .chunk_get(&envelope)
        .await
        .expect("fetch")
        .expect("the envelope is stored");
    assert_eq!(chunk.content, envelope_bytes);

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_private_upload_pays_its_withheld_envelope_with_the_content() {
    let (client, testnet) = setup().await;
    let chain = ListingChain::new(testnet.evm_network()).expect("chain reader");
    let (file, data) = input(0x11);
    let options = EnvelopeOptions::private().with_metadata(Metadata {
        content_type: Some("application/octet-stream".into()),
        name: Some("private.bin".into()),
    });
    let result = client
        .file_upload_with_visibility_and_progress(
            file.path(),
            PaymentMode::Auto,
            Visibility::Envelope(options.clone()),
            None,
        )
        .await
        .expect("upload");

    let content_chunks = result.data_map.infos().len();
    assert_eq!(result.total_chunks, content_chunks + 1);
    assert_eq!(result.chunks_stored, result.total_chunks);
    assert_eq!(
        result.data_map_address, None,
        "a private file has no download address"
    );
    let envelope = result.envelope.clone().expect("an envelope");
    assert!(envelope.salt.is_some());
    assert!(envelope.proof_checked, "{:?}", envelope.proof_problem);
    let record = envelope.proof.clone().expect("a record");
    assert_eq!(record.address, envelope.address());

    // One payment for the content and the envelope: the envelope's
    // transaction paid every chunk.
    assert_eq!(
        payments_in(&chain, &record.tx_hash).await,
        result.total_chunks
    );

    // The envelope is on the network, withholding its data map.
    let chunk = client
        .chunk_get(&envelope.address())
        .await
        .expect("fetch")
        .expect("the envelope is stored");
    let stored = Envelope::from_bytes(&chunk.content).expect("an envelope");
    assert!(stored.is_withheld());
    assert_eq!(stored.flags(), options.flags());
    assert!(matches!(
        client.data_map_fetch(&envelope.address()).await,
        Err(Error::DataMapWithheld(_))
    ));

    // The record proves the upload from the chain alone and reveals the file.
    let proven = chain
        .check_proof(&record)
        .await
        .expect("the proof checks out");
    assert!(proven.data_map.as_ref() == Some(&result.data_map));

    // The transaction paid its quotes in quote-hash order, so the
    // envelope's log is where its quote hash falls, not always last.
    let (receipt, _) = chain
        .transaction(&record.tx_hash)
        .await
        .expect("chain answers")
        .expect("transaction on chain");
    let vault_logs: Vec<_> = receipt
        .logs
        .iter()
        .filter(|log| log.topics.first() == Some(&DATA_PAYMENT_MADE_TOPIC))
        .collect();
    let quote_hashes: Vec<[u8; 32]> = vault_logs.iter().map(|log| log.topics[3]).collect();
    let mut sorted = quote_hashes.clone();
    sorted.sort_unstable();
    assert_eq!(quote_hashes, sorted);
    let paid_quote = ant_core::data::paid_quote_hash(&record.quote).expect("a quote");
    let position = sorted.iter().position(|hash| *hash == paid_quote).unwrap();
    assert_eq!(proven.payment.log_index, vault_logs[position].log_index);
    let revealed = proof_data_map(&record).expect("revealed");
    let output = TempDir::new().unwrap();
    let path = output.path().join("private.bin");
    client
        .file_download(&revealed, &path)
        .await
        .expect("download");
    assert_eq!(std::fs::read(path).unwrap(), data);

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn an_unlisted_upload_reads_by_its_envelope_address() {
    let (client, testnet) = setup().await;
    let chain = ListingChain::new(testnet.evm_network()).expect("chain reader");
    let (file, data) = input(0x22);
    let options = EnvelopeOptions::unlisted().hiding([PaymentField::Quote]);
    let result = client
        .file_upload_with_visibility_and_progress(
            file.path(),
            PaymentMode::Single,
            Visibility::Envelope(options.clone()),
            None,
        )
        .await
        .expect("upload");
    let envelope = result.envelope.clone().expect("an envelope");
    assert_eq!(result.data_map_address, Some(envelope.address()));
    assert!(envelope.salt.is_none());
    let record = envelope.proof.clone().expect("a record");
    assert!(record.salt.is_none() && record.data_map.is_none());
    assert_eq!(
        payments_in(&chain, &record.tx_hash).await,
        result.total_chunks
    );
    chain
        .check_proof(&record)
        .await
        .expect("the proof checks out");

    let map = client
        .data_map_fetch(&envelope.address())
        .await
        .expect("the envelope carries the data map");
    assert!(map == result.data_map);
    let output = TempDir::new().unwrap();
    let path = output.path().join("unlisted.bin");
    client.file_download(&map, &path).await.expect("download");
    assert_eq!(std::fs::read(path).unwrap(), data);

    // Uploaded again from the same wallet with the same choices, before the
    // record was saved: the envelope is already stored, so nothing is paid
    // for it, and the record the first upload kept comes back.
    let upload_again = || {
        client.file_upload_with_visibility_and_progress(
            file.path(),
            PaymentMode::Single,
            Visibility::Envelope(options.clone()),
            None,
        )
    };
    let again = upload_again().await.expect("upload again");
    let again = again.envelope.expect("an envelope");
    assert_eq!(again.address(), envelope.address());
    assert_eq!(again.proof.as_ref(), Some(&record));
    assert!(again.proof_checked, "{:?}", again.proof_problem);
    // Once the record is saved and the kept copy forgotten, a later upload
    // has no record: it paid for nothing.
    forget_upload_record(&envelope.address()).expect("forget");
    let third = upload_again().await.expect("upload a third time");
    let third = third.envelope.expect("an envelope");
    assert!(third.proof.is_none());
    assert!(third
        .proof_problem
        .is_some_and(|problem| problem.contains("already stored")));

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_kept_record_goes_back_only_to_the_account_that_paid() {
    let (client, testnet) = setup().await;
    let (file, _) = input(0x44);
    let options = EnvelopeOptions::unlisted().hiding([PaymentField::Quote]);
    let upload = |account: &'static str| {
        let payer = AccountPayer {
            wallet: testnet.wallet(),
            account,
        };
        let client = &client;
        let path = file.path().to_path_buf();
        let visibility = Visibility::Envelope(options.clone());
        async move {
            client
                .file_upload_with_payer(&path, visibility, PaymentMode::Single, &payer, None)
                .await
                .expect("upload")
                .envelope
                .expect("an envelope")
        }
    };
    let first = upload("account a").await;
    let record = first.proof.clone().expect("account a paid");
    assert!(first.proof_checked, "{:?}", first.proof_problem);
    // Another account uploading the same file finds the envelope stored and
    // gets no record: account a's, with its hidden quote, stays a's.
    let other = upload("account b").await;
    assert_eq!(other.address(), first.address());
    assert!(other.proof.is_none());
    assert!(other
        .proof_problem
        .is_some_and(|problem| problem.contains("already stored")));
    // Account a gets its own back.
    let again = upload("account a").await;
    assert_eq!(again.proof, Some(record));
    forget_upload_record(&first.address()).expect("forget");

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn hiding_everything_on_a_plain_private_upload_stores_no_envelope() {
    let (client, testnet) = setup().await;
    let (file, _) = input(0x33);
    let options = EnvelopeOptions {
        shown: ShownFields::NONE,
        ..EnvelopeOptions::private()
    };
    let result = client
        .file_upload_with_visibility_and_progress(
            file.path(),
            PaymentMode::Auto,
            Visibility::Envelope(options),
            None,
        )
        .await
        .expect("upload");
    assert!(result.envelope.is_none());
    assert_eq!(result.total_chunks, result.data_map.infos().len());
    assert_eq!(result.data_map_address, None);

    drop(client);
    testnet.teardown().await;
}

/// A forced-merkle upload with a listed envelope would pay the content in a
/// batch and the envelope per chunk after it. darwin-node refuses the batch
/// at quote time, so nothing is paid; the same upload paid per chunk then
/// pays the envelope with the content, and its record checks out.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_forced_merkle_upload_with_an_envelope_is_refused_before_anything_is_paid() {
    let (client, testnet) = setup_merkle_sized().await;
    let chain = ListingChain::new(testnet.evm_network()).expect("chain reader");
    let (file, data) = input(0x44);
    let upload = |mode| {
        client.file_upload_with_visibility_and_progress(
            file.path(),
            mode,
            Visibility::Envelope(EnvelopeOptions::listed()),
            None,
        )
    };
    let before = wallet_spend(testnet.wallet()).await;
    let error = upload(PaymentMode::Merkle)
        .await
        .expect_err("darwin-node refuses batch payments");
    assert_batch_refused(&error);
    assert_eq!(
        wallet_spend(testnet.wallet()).await,
        before,
        "nothing may be paid for a refused batch"
    );

    let result = upload(PaymentMode::Single).await.expect("upload");
    assert_eq!(result.payment_mode_used, PaymentMode::Single);
    assert_eq!(result.total_chunks, result.data_map.infos().len() + 1);
    assert_eq!(result.chunks_stored, result.total_chunks);
    let envelope = result.envelope.clone().expect("an envelope");
    assert!(envelope.proof_checked, "{:?}", envelope.proof_problem);
    let record = envelope.proof.clone().expect("a record");
    // The envelope's transaction paid every chunk, the envelope's among them.
    assert_eq!(
        payments_in(&chain, &record.tx_hash).await,
        result.total_chunks
    );
    chain
        .check_proof(&record)
        .await
        .expect("the proof checks out");

    let map = client
        .data_map_fetch(&envelope.address())
        .await
        .expect("readable");
    let output = TempDir::new().unwrap();
    let path = output.path().join("listed.bin");
    client.file_download(&map, &path).await.expect("download");
    assert_eq!(std::fs::read(path).unwrap(), data);

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn an_external_signer_pays_the_envelope_in_the_same_intent() {
    use ant_core::data::{ExternalPaymentInfo, FinalizeOutcome};
    use ant_protocol::evm::{QuoteHash, TxHash};
    use std::collections::HashMap;

    let (client, testnet) = setup().await;
    let chain = ListingChain::new(testnet.evm_network()).expect("chain reader");
    let (file, data) = input(0x55);
    let prepared = client
        .file_prepare_upload_with_mode(
            file.path(),
            Visibility::Envelope(EnvelopeOptions::private()),
            PaymentMode::Auto,
            None,
        )
        .await
        .expect("prepare");
    let envelope = prepared.envelope.clone().expect("an envelope");
    assert_eq!(prepared.data_map_address, None);
    let payments = match &prepared.payment_info {
        ExternalPaymentInfo::WaveBatch {
            prepared_chunks,
            payment_intent,
        } => {
            assert!(prepared_chunks
                .iter()
                .any(|chunk| chunk.address == envelope.address()));
            payment_intent.payments.clone()
        }
        other => panic!("expected a wave batch, got {other:?}"),
    };
    let (tx_hash_map, _gas) = testnet
        .wallet()
        .pay_for_quotes(payments)
        .await
        .expect("pay");
    let tx_hash_map: HashMap<QuoteHash, TxHash> = tx_hash_map.into_iter().collect();
    let result = match client
        .finalize_upload_resumable(prepared, &tx_hash_map)
        .await
        .expect("finalize")
    {
        FinalizeOutcome::Complete(result) => result,
        FinalizeOutcome::Partial { result, .. } => panic!("partial: {result:?}"),
    };
    assert_eq!(result.chunks_stored, result.total_chunks);
    let envelope = result.envelope.clone().expect("an envelope");
    assert!(envelope.proof_checked, "{:?}", envelope.proof_problem);
    let record = envelope.proof.clone().expect("a record");
    assert_eq!(
        payments_in(&chain, &record.tx_hash).await,
        result.total_chunks
    );
    let proven = chain
        .check_proof(&record)
        .await
        .expect("the proof checks out");
    assert!(proven.data_map.as_ref() == Some(&result.data_map));
    assert!(client
        .chunk_get(&envelope.address())
        .await
        .unwrap()
        .is_some());
    let output = TempDir::new().unwrap();
    let path = output.path().join("external.bin");
    client
        .file_download(&result.data_map, &path)
        .await
        .expect("download");
    assert_eq!(std::fs::read(path).unwrap(), data);

    // Merkle batches can't carry the envelope's payment: refused before
    // anything is quoted or paid.
    let (file, _) = input(0x56);
    assert!(matches!(
        client
            .file_prepare_upload_with_mode(
                file.path(),
                Visibility::Envelope(EnvelopeOptions::private()),
                PaymentMode::Merkle,
                None,
            )
            .await,
        Err(Error::InvalidData(_))
    ));

    // A client without an EVM network: said before payment, and finalize
    // still stores everything and builds the record, unchecked.
    let node = testnet.node(3).expect("Node 3 should exist");
    let bare = Client::from_node(Arc::clone(&node), test_client_config());
    let (file, data) = input(0x57);
    let prepared = bare
        .file_prepare_upload_with_mode(
            file.path(),
            Visibility::Envelope(EnvelopeOptions::private()),
            PaymentMode::Auto,
            None,
        )
        .await
        .expect("prepare without an EVM network");
    let problem = prepared
        .envelope
        .as_ref()
        .and_then(|envelope| envelope.proof_problem.clone())
        .expect("said before payment");
    assert!(problem.contains("no EVM network"), "{problem}");
    let payments = match &prepared.payment_info {
        ExternalPaymentInfo::WaveBatch { payment_intent, .. } => payment_intent.payments.clone(),
        other => panic!("expected a wave batch, got {other:?}"),
    };
    let (tx_hash_map, _gas) = testnet
        .wallet()
        .pay_for_quotes(payments)
        .await
        .expect("pay");
    let tx_hash_map: HashMap<QuoteHash, TxHash> = tx_hash_map.into_iter().collect();
    let result = bare
        .finalize_upload(prepared, &tx_hash_map)
        .await
        .expect("finalize never fails for want of an EVM network");
    assert_eq!(result.chunks_stored, result.total_chunks);
    let envelope = result.envelope.clone().expect("an envelope");
    assert!(!envelope.proof_checked);
    let problem = envelope.proof_problem.clone().unwrap_or_default();
    assert!(problem.contains("no EVM network"), "{problem}");
    let record = envelope.proof.clone().expect("a record, unchecked");
    let proven = chain
        .check_proof(&record)
        .await
        .expect("the unchecked record checks out");
    assert!(proven.data_map.as_ref() == Some(&result.data_map));
    let path = output.path().join("bare.bin");
    bare.file_download(&result.data_map, &path)
        .await
        .expect("download");
    assert_eq!(std::fs::read(path).unwrap(), data);

    drop(bare);
    drop(client);
    testnet.teardown().await;
}

/// The library's file shortcuts store envelopes by default, every payment
/// field shown: `file_prepare_upload` prepares a private one (withheld, not
/// in the index, with a salt), and `file_upload_public_with_progress` stores
/// an unlisted one (readable, not in the index) at the upload's address.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn the_file_shortcuts_store_envelopes_by_default() {
    let (client, testnet) = setup().await;

    let (file, _) = input(0x31);
    let prepared = client
        .file_prepare_upload(file.path())
        .await
        .expect("prepare");
    let private = prepared.envelope.as_ref().expect("a private envelope");
    let flags = private.envelope.flags();
    assert_eq!(flags.shown, ShownFields::ALL);
    assert!(!flags.in_index);
    assert!(flags.withheld);
    assert!(private.salt.is_some());

    let (file, _) = input(0x32);
    let result = client
        .file_upload_public_with_progress(file.path(), PaymentMode::Single, None)
        .await
        .expect("upload");
    let unlisted = result.envelope.clone().expect("an unlisted envelope");
    let flags = unlisted.envelope.flags();
    assert_eq!(flags.shown, ShownFields::ALL);
    assert!(!flags.in_index);
    assert!(!flags.withheld);
    assert!(unlisted.salt.is_none());
    assert_eq!(result.data_map_address, Some(unlisted.address()));

    drop(client);
    testnet.teardown().await;
}
