//! File upload and download through streaming self-encryption: the
//! envelope `darwin file upload` stores by default, streaming downloads,
//! external-signer prepares and the public wave-batch round trip, and a
//! retry after funding that reuses the file's checkpoint.

use crate::support::runner::Case;
use crate::support::{test_client_config, MiniTestnet, CLIENT_NODE};
use ant_core::ant_listings::Envelope;
use ant_core::data::{
    compute_address, forget_upload_record, Client, EnvelopeOptions, ExternalPaymentInfo,
    ListingChain, PaymentMode, Visibility,
};
use ant_protocol::evm::{QuoteHash, TxHash};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tempfile::{NamedTempFile, TempDir};

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network("file::round_trip", test_file_upload_download_round_trip),
        Case::on_network(
            "file::download_to_sender_multibatch",
            test_file_download_to_sender_multibatch_round_trip,
        ),
        Case::on_network(
            "file::prepare_upload_visibility",
            test_file_prepare_upload_visibility,
        ),
        Case::on_network(
            "file::public_upload_round_trip_wave_batch",
            test_public_upload_round_trip_wave_batch,
        ),
        Case::on_network(
            "file::retry_after_funding_uses_existing_checkpoint",
            test_file_retry_after_funding_uses_existing_checkpoint,
        ),
    ]
}

async fn test_file_upload_download_round_trip(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let mut input_file = NamedTempFile::new().expect("create temp file");
    let data = vec![0x42u8; 4096];
    input_file.write_all(&data).expect("write temp file");
    input_file.flush().expect("flush temp file");

    let result = client
        .file_upload(input_file.path())
        .await
        .expect("file_upload should succeed");

    assert!(
        result.chunks_stored >= 3,
        "self-encryption produces at least 3 chunks"
    );

    // As `darwin file upload` stores a file by default: in a private
    // envelope that shows every payment field, with the record proving its
    // payment, which checks out against the chain.
    let envelope = result
        .envelope
        .clone()
        .expect("file_upload stores an envelope");
    assert!(!envelope.readable(), "a private envelope");
    assert!(envelope.salt.is_some());
    assert_eq!(result.data_map_address, None, "no public address");
    assert_eq!(
        envelope.envelope.flags(),
        EnvelopeOptions::private().flags()
    );
    assert!(envelope.proof_checked, "{:?}", envelope.proof_problem);
    let record = envelope.proof.clone().expect("a record of its payment");
    assert_eq!(record.address, envelope.address());
    ListingChain::new(testnet.evm_network())
        .expect("chain reader")
        .check_proof(&record)
        .await
        .expect("the record checks out against the chain");
    let stored = client
        .chunk_get(&envelope.address())
        .await
        .expect("fetch")
        .expect("the envelope is stored");
    let stored = Envelope::from_bytes(&stored.content).expect("an envelope");
    assert!(stored.is_withheld());
    assert_eq!(stored.flags(), EnvelopeOptions::private().flags());
    forget_upload_record(&envelope.address()).expect("forget the kept record");

    let output_dir = TempDir::new().expect("create temp dir");
    let output_path = output_dir.path().join("downloaded.bin");

    let bytes_written = client
        .file_download(&result.data_map, &output_path)
        .await
        .expect("file_download should succeed");

    let downloaded = std::fs::read(&output_path).expect("read output file");
    assert_eq!(downloaded, data, "downloaded content should match original");
    assert_eq!(
        bytes_written,
        data.len() as u64,
        "bytes_written should match original size"
    );
}

/// Streaming download: `file_download_to_sender` must yield exactly the bytes,
/// in order, that the file contained — without buffering the whole file. Uses
/// a multi-batch payload so the streaming-decrypt path runs more than one
/// batch, then reassembles the stream and asserts equality with the source.
async fn test_file_download_to_sender_multibatch_round_trip(testnet: Arc<MiniTestnet>) {
    use tokio::sync::mpsc;

    let client = testnet.client();

    let mut input_file = NamedTempFile::new().expect("create temp file");
    // ~1 MiB of varied bytes → many self-encryption chunks (multiple batches).
    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    input_file.write_all(&data).expect("write temp file");
    input_file.flush().expect("flush temp file");

    let result = client
        .file_upload(input_file.path())
        .await
        .expect("file_upload should succeed");

    // Channel item type is inferred from `file_download_to_sender`'s signature.
    let (tx, mut rx) = mpsc::channel(8);
    let data_map = result.data_map.clone();
    let dl = tokio::spawn(async move { client.file_download_to_sender(&data_map, tx, None).await });

    let mut streamed: Vec<u8> = Vec::with_capacity(data.len());
    let mut chunk_count = 0usize;
    while let Some(item) = rx.recv().await {
        let chunk = item.expect("stream chunk should be Ok");
        // A buggy "send one empty/sentinel then drop" producer would still
        // close the channel; assert each delivered chunk carries real bytes.
        assert!(!chunk.is_empty(), "streamed chunk should be non-empty");
        chunk_count += 1;
        streamed.extend_from_slice(&chunk);
    }

    let bytes_streamed = dl
        .await
        .expect("download task should join")
        .expect("file_download_to_sender should succeed");

    // The whole point of the streaming path: a multi-batch payload must arrive
    // as more than one segment, not buffered and emitted in one shot.
    assert!(
        chunk_count >= 2,
        "multi-batch payload should stream as ≥2 segments, got {chunk_count}"
    );
    assert_eq!(streamed, data, "streamed content should match original");
    assert_eq!(
        bytes_streamed,
        data.len() as u64,
        "bytes_streamed should match original size"
    );
}

/// External-signer prepare must bundle the serialized DataMap as one extra
/// paid chunk when `Visibility::Public` is requested, and must record the
/// resulting chunk address on the `PreparedUpload`. Private prepare must
/// leave that address unset.
async fn test_file_prepare_upload_visibility(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let data = vec![0x37u8; 4096];
    let mut input_file = NamedTempFile::new().expect("create temp file");
    input_file.write_all(&data).expect("write temp file");
    input_file.flush().expect("flush temp file");

    let private = client
        .file_prepare_upload_with_visibility(input_file.path(), Visibility::Private)
        .await
        .expect("private prepare should succeed");

    assert!(
        private.data_map_address.is_none(),
        "private uploads must not publish a DataMap address"
    );

    let public = client
        .file_prepare_upload_with_visibility(input_file.path(), Visibility::Public)
        .await
        .expect("public prepare should succeed");

    let public_addr = public
        .data_map_address
        .expect("public prepare must record the DataMap chunk address");

    // The recorded address must match a fresh hash of the serialized DataMap,
    // proving the address refers to exactly the chunk that was added to the
    // payment batch (and that `data_map_fetch` on this address will later
    // yield the same DataMap we're holding).
    let expected_bytes = rmp_serde::to_vec(&public.data_map).expect("serialize DataMap");
    let expected_addr = compute_address(&expected_bytes);
    assert_eq!(
        public_addr, expected_addr,
        "data_map_address must equal compute_address(rmp_serde::to_vec(&data_map))"
    );

    // A small file produces a wave-batch payment (well under the merkle
    // threshold), and the datamap chunk must appear in that batch.
    match (&private.payment_info, &public.payment_info) {
        (
            ExternalPaymentInfo::WaveBatch {
                prepared_chunks: priv_chunks,
                ..
            },
            ExternalPaymentInfo::WaveBatch {
                prepared_chunks: pub_chunks,
                ..
            },
        ) => {
            assert_eq!(
                pub_chunks.len(),
                priv_chunks.len() + 1,
                "public prepare must add exactly one chunk (the serialized DataMap) to the batch"
            );
            assert!(
                pub_chunks.iter().any(|c| c.address == public_addr),
                "the extra chunk must be the DataMap chunk at the recorded address"
            );
        }
        other => panic!("expected wave-batch for a 4KB file, got {other:?}"),
    }
}

/// Full public-upload round-trip (wave-batch path).
///
/// Simulates the external-signer flow end-to-end: prepare → sign payments
/// via the testnet wallet → finalize → `data_map_fetch` using only the
/// returned address → `file_download` → assert recovered bytes equal the
/// original. Proves the data_map_address actually refers to a retrievable
/// DataMap on the network, not just a hash recorded in memory.
async fn test_public_upload_round_trip_wave_batch(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let original = vec![0x5au8; 4096];
    let mut input_file = NamedTempFile::new().expect("create temp file");
    input_file.write_all(&original).expect("write temp file");
    input_file.flush().expect("flush temp file");

    // Phase 1: prepare as public.
    let prepared = client
        .file_prepare_upload_with_visibility(input_file.path(), Visibility::Public)
        .await
        .expect("public prepare should succeed");
    let data_map_address = prepared
        .data_map_address
        .expect("public prepare must record the DataMap address");

    // Phase 2: simulate an external signer by paying for the quotes with the
    // testnet wallet and collecting the resulting (quote_hash, tx_hash) map.
    let payments = match &prepared.payment_info {
        ExternalPaymentInfo::WaveBatch { payment_intent, .. } => payment_intent.payments.clone(),
        other => panic!("expected wave-batch payment for a 4KB file, got {other:?}"),
    };
    let (tx_hash_map, _gas) = testnet
        .wallet()
        .pay_for_quotes(payments)
        .await
        .expect("testnet wallet should pay for quotes");
    let tx_hash_map: HashMap<QuoteHash, TxHash> = tx_hash_map.into_iter().collect();

    // Phase 3: finalize. The data map chunk is stored alongside the data
    // chunks in this single call — no second network trip needed.
    let result = client
        .finalize_upload(prepared, &tx_hash_map)
        .await
        .expect("finalize_upload should succeed");
    assert_eq!(
        result.data_map_address,
        Some(data_map_address),
        "FileUploadResult must carry the DataMap address forward from PreparedUpload"
    );

    // Phase 4: a fresh retriever can fetch the data map using only the
    // shared address — they did not participate in the upload.
    let fetched_data_map = client
        .data_map_fetch(&data_map_address)
        .await
        .expect("data_map_fetch must retrieve the stored DataMap");

    // Phase 5: download + verify content.
    let output_dir = TempDir::new().expect("create output temp dir");
    let output_path = output_dir.path().join("round_trip_out.bin");
    let bytes_written = client
        .file_download(&fetched_data_map, &output_path)
        .await
        .expect("file_download should succeed");
    assert_eq!(
        bytes_written,
        original.len() as u64,
        "bytes_written should equal original size"
    );

    let downloaded = std::fs::read(&output_path).expect("read downloaded file");
    assert_eq!(
        downloaded, original,
        "downloaded bytes must equal the original file"
    );
}

/// A failed wallet preflight must not permanently poison the file's checkpoint.
async fn test_file_retry_after_funding_uses_existing_checkpoint(testnet: Arc<MiniTestnet>) {
    use ant_protocol::evm::{Amount, Wallet};
    let node = testnet.node(CLIENT_NODE).unwrap();
    let wallet = Wallet::new_with_random_wallet(testnet.evm_network().clone());
    let address = wallet.address();
    let client = Client::from_node(node, test_client_config()).with_wallet(wallet);
    let mut input = NamedTempFile::new().unwrap();
    let data = vec![0x76; 4096];
    input.write_all(&data).unwrap();
    input.flush().unwrap();
    let error = client
        .file_upload_with_mode(input.path(), PaymentMode::Single)
        .await
        .unwrap_err();
    assert!(
        error.to_string().to_lowercase().contains("insufficient"),
        "{error}"
    );
    testnet
        .wallet()
        .transfer_tokens(address, Amount::from(100_000_000_000_000_000_000u128))
        .await
        .unwrap();
    testnet
        .wallet()
        .transfer_gas_tokens(address, Amount::from(1_000_000_000_000_000_000u64))
        .await
        .unwrap();
    let result = client
        .file_upload_with_mode(input.path(), PaymentMode::Single)
        .await
        .unwrap();
    let output = TempDir::new().unwrap();
    let path = output.path().join("recovered.bin");
    client.file_download(&result.data_map, &path).await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), data);
}
