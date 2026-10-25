//! Merkle (batch) payments against darwin-node, which refuses them.
//!
//! A batch is paid on-chain before any storer sees a PUT, so a node that
//! refused the PUTs afterwards would let the client spend for nothing.
//! darwin-node refuses batches up front: every merkle candidate request is
//! answered with `BATCH_PAYMENTS_REFUSED` at quote time, before anything is
//! signed, and every merkle-tagged proof is refused on a PUT. These cases run
//! this client's batch paths (wallet, low-level and external signer) against
//! the shared darwin-node testnet on Anvil, and pin what the refusal leaves:
//! nothing paid (the wallet sent no transaction and holds the same tokens),
//! nothing stored, and a client that still pays per chunk.
//!
//! These tests used to run on upstream's ant-node from crates.io, where batch
//! payments succeed. The batch arithmetic they also checked (the split either
//! side of the 256-leaf boundary, the padded leaves billed) needs no nodes and
//! is pinned in `merkle_unit.rs`; darwin-node's own tests send it well-formed,
//! tampered and paid merkle proofs (its `tests/e2e/merkle_payment.rs`).

use crate::envelope::payments_in;
use crate::support::runner::Case;
use crate::support::{
    assert_batch_refused, test_client_config, wallet_spend, MiniTestnet, BATCH_PAYMENTS_REFUSED,
};
use ant_core::data::client::merkle::PaymentMode;
use ant_core::data::{
    compute_address, forget_upload_record, Client, ClientConfig, EnvelopeOptions,
    ExternalPaymentInfo, ListingChain, Visibility,
};
use ant_protocol::evm::{QuoteHash, TxHash};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tempfile::{NamedTempFile, TempDir};

/// Chunk size for the payment-only cases (small, fast to hash).
const TEST_CHUNK_SIZE: usize = 1024;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network(
            "merkle::a_forced_merkle_file_upload_is_refused_before_anything_is_paid",
            a_forced_merkle_file_upload_is_refused_before_anything_is_paid,
        ),
        Case::on_network(
            "merkle::a_forced_merkle_data_upload_is_refused_before_anything_is_paid",
            a_forced_merkle_data_upload_is_refused_before_anything_is_paid,
        ),
        Case::on_network(
            "merkle::a_put_carrying_a_merkle_proof_is_refused",
            a_put_carrying_a_merkle_proof_is_refused,
        ),
        Case::on_network(
            "merkle::a_merkle_batch_payment_is_refused_either_side_of_the_batch_boundary",
            a_merkle_batch_payment_is_refused_either_side_of_the_batch_boundary,
        ),
        Case::on_network(
            "merkle::an_external_signer_is_given_per_chunk_payments_instead_of_merkle_batches",
            an_external_signer_is_given_per_chunk_payments_instead_of_merkle_batches,
        ),
        Case::on_network(
            "merkle::merkle_sub_batches_for_an_external_signer_are_refused_at_quote_time",
            merkle_sub_batches_for_an_external_signer_are_refused_at_quote_time,
        ),
    ]
}

/// A client that takes its whole routing table for a close group, as the
/// batch payments these cases attempt were made before.
pub fn merkle_client(testnet: &MiniTestnet) -> Client {
    testnet.client_with(ClientConfig {
        close_group_size: 20,
        ..test_client_config()
    })
}

/// A file of `size` patterned bytes, distinct for each `seed`.
fn patterned_file(size: usize, seed: u8) -> (NamedTempFile, Vec<u8>) {
    let data: Vec<u8> = (0u8..=255)
        .cycle()
        .take(size)
        .map(|byte| byte ^ seed)
        .collect();
    let mut file = NamedTempFile::new().expect("create temp file");
    file.write_all(&data).expect("write temp file");
    file.flush().expect("flush temp file");
    (file, data)
}

/// A forced-merkle file upload is refused at quote time, before anything is
/// paid or stored, and the refusal doesn't stop the client: the same file
/// then uploads per chunk, and downloads whole. Both with a listed envelope,
/// which would pay the content in a batch and the envelope per chunk after
/// it (paid per chunk, the envelope is paid with the content, and its record
/// checks out), and in the default private envelope.
async fn a_forced_merkle_file_upload_is_refused_before_anything_is_paid(testnet: Arc<MiniTestnet>) {
    let client = merkle_client(&testnet);
    let chain = ListingChain::new(testnet.evm_network()).expect("chain reader");

    for (seed, listed) in [(0x5c_u8, true), (0x00, false)] {
        // 500KB file — self-encryption produces 3+ chunks
        let (input_file, data) = patterned_file(500_000, seed);

        let before = wallet_spend(testnet.wallet()).await;
        let error = upload(&client, input_file.path(), listed, PaymentMode::Merkle)
            .await
            .expect_err("darwin-node refuses batch payments");
        assert_batch_refused(&error);
        assert_eq!(
            wallet_spend(testnet.wallet()).await,
            before,
            "nothing may be paid for a refused batch (listed: {listed})"
        );

        // Not a verdict about this client: it goes on paying per chunk.
        let result = upload(&client, input_file.path(), listed, PaymentMode::Single)
            .await
            .expect("a per-chunk upload after the refusal");
        assert_eq!(result.payment_mode_used, PaymentMode::Single);
        assert!(
            result.chunks_stored >= 3,
            "self-encryption should produce at least 3 chunks, got {}",
            result.chunks_stored
        );
        assert!(
            wallet_spend(testnet.wallet()).await.0 > before.0,
            "the per-chunk upload paid"
        );
        let envelope = result.envelope.clone().expect("an envelope");
        assert!(envelope.proof_checked, "{:?}", envelope.proof_problem);
        let record = envelope.proof.clone().expect("a record");
        forget_upload_record(&envelope.address()).expect("forget the kept record");
        if listed {
            assert_eq!(result.total_chunks, result.data_map.infos().len() + 1);
            assert_eq!(result.chunks_stored, result.total_chunks);
            // The envelope's transaction paid every chunk, the envelope's
            // among them.
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
            assert!(map == result.data_map);
        }

        let output_dir = TempDir::new().expect("create temp dir");
        let output_path = output_dir.path().join("per_chunk_downloaded.bin");
        let bytes_written = client
            .file_download(&result.data_map, &output_path)
            .await
            .expect("file download should succeed");
        let downloaded = std::fs::read(&output_path).expect("read downloaded file");
        assert_eq!(downloaded, data, "downloaded content must match original");
        assert_eq!(bytes_written, data.len() as u64, "bytes_written must match");
    }
}

/// Upload `path` with a listed envelope, or as `file_upload_with_mode` does,
/// in the default private one.
async fn upload(
    client: &Client,
    path: &std::path::Path,
    listed: bool,
    mode: PaymentMode,
) -> ant_core::data::Result<ant_core::data::FileUploadResult> {
    if listed {
        client
            .file_upload_with_visibility_and_progress(
                path,
                mode,
                Visibility::Envelope(EnvelopeOptions::listed()),
                None,
            )
            .await
    } else {
        client.file_upload_with_mode(path, mode).await
    }
}

/// A forced-merkle upload of in-memory data is refused the same way, and
/// stores none of its chunks.
async fn a_forced_merkle_data_upload_is_refused_before_anything_is_paid(testnet: Arc<MiniTestnet>) {
    let client = merkle_client(&testnet);

    let data: Vec<u8> = (0u8..=255).rev().cycle().take(100_000).collect();
    let (data_map, _) = self_encryption::encrypt(bytes::Bytes::from(data.clone()))
        .expect("encrypt the data as the upload does");

    let before = wallet_spend(testnet.wallet()).await;
    let error = client
        .data_upload_with_mode(bytes::Bytes::from(data), PaymentMode::Merkle)
        .await
        .expect_err("darwin-node refuses batch payments");
    assert_batch_refused(&error);
    assert_eq!(wallet_spend(testnet.wallet()).await, before);

    for info in data_map.infos() {
        assert!(
            client
                .chunk_get(&info.dst_hash.0)
                .await
                .expect("chunk_get answers")
                .is_none(),
            "no chunk of a refused upload may be stored"
        );
    }
}

/// A PUT carrying a merkle proof is refused, whatever the proof, so no chunk
/// is stored on a batch payment: neither one that is not in the proof's tree
/// nor one that is. darwin-node refuses on the proof's tag, before any of
/// upstream's merkle checks; its own tests send it well-formed and tampered
/// proofs, which a client can no longer get paid for.
async fn a_put_carrying_a_merkle_proof_is_refused(testnet: Arc<MiniTestnet>) {
    let client = merkle_client(&testnet);

    // The shape of a merkle proof as a client sends it: the tag, then the
    // proof (here bytes no node reads past the tag).
    let mut proof = vec![ant_protocol::PROOF_TAG_MERKLE];
    proof.extend([0x5a; 255]);

    for content in [
        bytes::Bytes::from(vec![0u8; TEST_CHUNK_SIZE]),
        bytes::Bytes::from("this content was in no merkle tree"),
    ] {
        let address = compute_address(&content);
        let peers = client
            .network()
            .find_closest_peers(&address, 1)
            .await
            .expect("should find peers");
        let (target_peer, target_addrs) = &peers[0];

        let error = client
            .chunk_put_with_proof(content, proof.clone(), target_peer, target_addrs)
            .await
            .expect_err("a merkle proof is refused");
        assert!(
            error.to_string().contains(BATCH_PAYMENTS_REFUSED),
            "expected darwin-node's refusal of batch payments, got: {error}"
        );
        assert!(
            client
                .chunk_get(&address)
                .await
                .expect("chunk_get answers")
                .is_none(),
            "a chunk PUT with a merkle proof must not be stored"
        );
    }
}

/// The low-level batch payment is refused at quote time either side of the
/// 256-leaf boundary: one tree of 65 addresses, and 257 split across two, the
/// second of which is never reached. Nothing is paid for either, not even the
/// first of the two.
async fn a_merkle_batch_payment_is_refused_either_side_of_the_batch_boundary(
    testnet: Arc<MiniTestnet>,
) {
    let client = merkle_client(&testnet);

    // Distinct, deterministic addresses. Payment binds to addresses only; the
    // chunks themselves are never stored by this test.
    let addresses = |count: usize, tag: u8| -> Vec<[u8; 32]> {
        (0..count)
            .map(|i| {
                let mut addr = [0u8; 32];
                addr[0] = tag;
                addr[1..9].copy_from_slice(&(i as u64).to_be_bytes());
                addr
            })
            .collect()
    };

    for (count, tag) in [(65usize, 0xA1u8), (257usize, 0xB2u8)] {
        let before = wallet_spend(testnet.wallet()).await;
        let error = client
            .pay_for_merkle_batch(&addresses(count, tag), 0, TEST_CHUNK_SIZE as u64)
            .await
            .expect_err("darwin-node refuses batch payments");
        assert_batch_refused(&error);
        assert_eq!(
            wallet_spend(testnet.wallet()).await,
            before,
            "{count} addresses: nothing may be paid"
        );
    }
}

/// An external signer asking for merkle sub-batches is never handed one to
/// pay: the forced-merkle prepare (cap 3, public, so it would have been two
/// sub-batches) comes back as one per-chunk payment intent, since the nodes
/// refused the batches' candidates, and the upload completes per chunk: paid
/// by the testnet wallet as an external signer would, finalized, and read back
/// from its public address.
async fn an_external_signer_is_given_per_chunk_payments_instead_of_merkle_batches(
    testnet: Arc<MiniTestnet>,
) {
    let mut client = merkle_client(&testnet);
    client.config_mut().merkle_external_batch_cap = Some(3);

    let (input_file, data) = patterned_file(500_000, 0xa7);
    let prepared = client
        .file_prepare_upload_with_mode(
            input_file.path(),
            Visibility::Public,
            PaymentMode::Merkle,
            None,
        )
        .await
        .expect("the prepare falls back to per-chunk payment");
    let public_address = prepared
        .data_map_address
        .expect("public prepare must record the DataMap address");
    let payments = match &prepared.payment_info {
        ExternalPaymentInfo::WaveBatch { payment_intent, .. } => payment_intent.payments.clone(),
        ExternalPaymentInfo::Merkle {
            prepared_batches, ..
        } => panic!(
            "darwin-node refuses batch payments, yet {} merkle sub-batch(es) were prepared",
            prepared_batches.len()
        ),
    };

    let (tx_hash_map, _gas) = testnet
        .wallet()
        .pay_for_quotes(payments)
        .await
        .expect("the external signer pays per chunk");
    let tx_hash_map: HashMap<QuoteHash, TxHash> = tx_hash_map.into_iter().collect();
    let result = client
        .finalize_upload(prepared, &tx_hash_map)
        .await
        .expect("finalize stores every chunk");
    assert_eq!(result.payment_mode_used, PaymentMode::Single);
    assert_eq!(result.chunks_stored, result.total_chunks);

    let fetched_map = client
        .data_map_fetch(&public_address)
        .await
        .expect("public DataMap chunk should be retrievable");
    let output_dir = TempDir::new().expect("create temp dir");
    let output_path = output_dir.path().join("external_per_chunk.bin");
    client
        .file_download(&fetched_map, &output_path)
        .await
        .expect("download should succeed");
    let downloaded = std::fs::read(&output_path).expect("read downloaded file");
    assert_eq!(downloaded, data, "downloaded content must match original");
}

/// Merkle sub-batches prepared directly for an external signer are refused at
/// quote time, before there is anything to sign: four addresses under cap 3,
/// two sub-batches, neither prepared.
async fn merkle_sub_batches_for_an_external_signer_are_refused_at_quote_time(
    testnet: Arc<MiniTestnet>,
) {
    let client = merkle_client(&testnet);

    let addresses: Vec<[u8; 32]> = (0..4u8)
        .map(|i| compute_address(&vec![i; TEST_CHUNK_SIZE]))
        .collect();
    let error = client
        .prepare_merkle_batches_external(
            &addresses,
            ant_protocol::DATA_TYPE_CHUNK,
            TEST_CHUNK_SIZE as u64,
            3,
        )
        .await
        .expect_err("darwin-node refuses batch payments");
    assert_batch_refused(&error);
}
