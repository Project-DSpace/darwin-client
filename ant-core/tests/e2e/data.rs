//! In-memory data upload and download through self-encryption, with real
//! EVM payments.

use crate::support::runner::Case;
use crate::support::MiniTestnet;
use bytes::Bytes;
use self_encryption::encrypt;
use self_encryption::MAX_CHUNK_SIZE;
use std::sync::Arc;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network("data::round_trip", test_data_upload_download_round_trip),
        Case::on_network(
            "data::shrunk_datamap_round_trip",
            test_data_shrunk_datamap_round_trip,
        ),
        Case::on_network(
            "data::deterministic_encryption",
            test_data_deterministic_encryption,
        ),
        Case::on_network(
            "data::partial_overlap_skips_payment_for_existing_chunks",
            test_data_upload_partial_overlap_skips_payment_for_existing_chunks,
        ),
        Case::on_network(
            "data::public_data_map_store_and_fetch",
            test_public_data_map_store_and_fetch,
        ),
    ]
}

/// Payload size that forces self-encryption to shrink the `DataMap`.
///
/// A file produces exactly 3 chunks until it exceeds `3 * MAX_CHUNK_SIZE`, and
/// self-encryption only shrinks a map with more than 3 chunk infos. Four full
/// chunks (`4 * MAX_CHUNK_SIZE`) clears that boundary regardless of the
/// configured chunk size, so the returned map has `is_child() == true`.
const SHRUNK_DATAMAP_PAYLOAD_BYTES: usize = 4 * MAX_CHUNK_SIZE;

async fn test_data_upload_download_round_trip(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    // Self-encryption requires at least 3072 bytes
    let content = Bytes::from(vec![0x43u8; 4096]);

    let result = client
        .data_upload(content.clone())
        .await
        .expect("data_upload should succeed");

    assert!(
        result.chunks_stored >= 3,
        "self-encryption produces at least 3 chunks"
    );

    let downloaded = client
        .data_download(&result.data_map)
        .await
        .expect("data_download should succeed");

    assert_eq!(
        downloaded, content,
        "downloaded content should match original"
    );

    let range = client
        .data_download_range(&result.data_map, 1020, 1500)
        .await
        .expect("shared range reader should succeed");
    assert_eq!(range, content.slice(1020..2520));
    assert!(client
        .data_download_range(&result.data_map, content.len(), 10)
        .await
        .unwrap()
        .is_empty());
}

/// Regression test: a payload large enough to shrink the `DataMap` must still
/// round-trip through `data_upload`/`data_download`.
///
/// Before the fix, `data_download` fed the shrunk map's wrapper-level `infos()`
/// straight to `self_encryption::decrypt`, which never fetched the root content
/// chunks and failed with `Encryption("... Missing chunk ...")`. Small payloads
/// (<= 3 chunks, flat map) hid the bug because they are never shrunk.
async fn test_data_shrunk_datamap_round_trip(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    // Patterned data so a correct round-trip must reproduce the exact bytes,
    // not merely match on length.
    let content: Vec<u8> = (0u8..=255)
        .cycle()
        .take(SHRUNK_DATAMAP_PAYLOAD_BYTES)
        .collect();
    let content = Bytes::from(content);

    let result = client
        .data_upload(content.clone())
        .await
        .expect("data_upload should succeed");

    // Guard: if this payload ever stops producing a shrunk (child) map, the
    // test would silently stop exercising the regression it protects against.
    assert!(
        result.data_map.is_child(),
        "payload of {} bytes should produce a shrunk (child) DataMap (infos={})",
        SHRUNK_DATAMAP_PAYLOAD_BYTES,
        result.data_map.infos().len()
    );

    let mut downloaded = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match client.data_download(&result.data_map).await {
            Ok(d) => {
                downloaded = Some(d);
                break;
            }
            Err(e) if attempt < 2 => {
                eprintln!("attempt {attempt}: data_download failed: {e}");
            }
            Err(e) => panic!("data_download of shrunk DataMap should succeed: {e}"),
        }
    }
    let downloaded = downloaded.expect("data_download should succeed after retries");

    assert_eq!(
        downloaded, content,
        "downloaded content should match original for a shrunk DataMap"
    );
}

async fn test_data_deterministic_encryption(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from(vec![0xAA; 4096]);

    let result1 = client
        .data_upload(content.clone())
        .await
        .expect("first upload should succeed");

    let result2 = client
        .data_upload(content.clone())
        .await
        .expect("second upload should succeed");

    // Verify download produces the original content (retry for CI transport flakiness)
    let mut downloaded = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match client.data_download(&result2.data_map).await {
            Ok(d) => {
                downloaded = Some(d);
                break;
            }
            Err(e) if attempt < 2 => {
                eprintln!("attempt {attempt}: data_download failed: {e}");
            }
            Err(e) => panic!("data_download should succeed: {e}"),
        }
    }
    let downloaded = downloaded.expect("data_download should succeed after retries");
    assert_eq!(
        downloaded, content,
        "downloaded content should match original after deterministic re-upload"
    );

    // Convergent encryption: same content produces same DataMap
    assert_eq!(
        result1.data_map.infos().len(),
        result2.data_map.infos().len(),
        "same content should produce same number of chunks"
    );

    // Verify chunk addresses match (convergent encryption property)
    for (a, b) in result1
        .data_map
        .infos()
        .iter()
        .zip(result2.data_map.infos().iter())
    {
        assert_eq!(
            a.dst_hash, b.dst_hash,
            "same content should produce same chunk addresses"
        );
    }
}

async fn test_data_upload_partial_overlap_skips_payment_for_existing_chunks(
    testnet: Arc<MiniTestnet>,
) {
    let client = testnet.client();

    // Use enough data to produce multiple encrypted chunks (self-encryption needs >= 3)
    let content = Bytes::from(vec![0xBB; 8192]);

    // Encrypt locally to discover what chunks will be produced
    let (_data_map, encrypted_chunks) = encrypt(content.clone()).expect("encrypt should succeed");
    assert!(
        encrypted_chunks.len() >= 3,
        "need at least 3 chunks, got {}",
        encrypted_chunks.len()
    );

    // Pre-store the FIRST encrypted chunk on the network
    let first_chunk_content = encrypted_chunks
        .first()
        .expect("should have first chunk")
        .content
        .clone();
    client
        .chunk_put(first_chunk_content)
        .await
        .expect("pre-storing one chunk should succeed");

    // Record balance AFTER pre-storing one chunk (this is our baseline)
    let balance_before = client
        .wallet()
        .expect("wallet should be set")
        .balance_of_tokens()
        .await
        .expect("balance query should succeed");

    // Upload the full data — chunk_put will be called for each encrypted chunk,
    // but the pre-stored one should be detected as AlreadyStored and skipped
    let result = client
        .data_upload(content.clone())
        .await
        .expect("data_upload should succeed");

    assert!(
        result.chunks_stored >= 3,
        "should store at least 3 chunks total"
    );

    let balance_after_partial = client
        .wallet()
        .expect("wallet should be set")
        .balance_of_tokens()
        .await
        .expect("balance query should succeed");

    // Balance should have decreased (we paid for N-1 new chunks)
    assert!(
        balance_after_partial < balance_before,
        "should have paid for the new chunks"
    );

    // Now upload the SAME data again — ALL chunks exist, so zero payment
    let balance_before_dup = balance_after_partial;
    let result2 = client
        .data_upload(content.clone())
        .await
        .expect("duplicate data_upload should succeed");

    assert_eq!(
        result.chunks_stored, result2.chunks_stored,
        "same content should produce same chunk count"
    );

    let balance_after_dup = client
        .wallet()
        .expect("wallet should be set")
        .balance_of_tokens()
        .await
        .expect("balance query should succeed");

    assert_eq!(
        balance_before_dup, balance_after_dup,
        "full duplicate upload should not spend any tokens"
    );

    // Verify the data is still downloadable and correct (retry for CI transport flakiness)
    let mut downloaded = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match client.data_download(&result.data_map).await {
            Ok(d) => {
                downloaded = Some(d);
                break;
            }
            Err(e) if attempt < 2 => {
                eprintln!("attempt {attempt}: data_download failed: {e}");
            }
            Err(e) => panic!("data_download should succeed: {e}"),
        }
    }
    let downloaded = downloaded.expect("data_download should succeed after retries");
    assert_eq!(downloaded, content, "downloaded content should match");
}

async fn test_public_data_map_store_and_fetch(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    // Upload data, get a DataMap
    let content = Bytes::from(vec![0xFFu8; 4096]);
    let result = client
        .data_upload(content.clone())
        .await
        .expect("data_upload should succeed");

    // Store the DataMap publicly (as a chunk on the network)
    let dm_address = client
        .data_map_store(&result.data_map)
        .await
        .expect("data_map_store should succeed");

    // Fetch it back by address
    let fetched_dm = client
        .data_map_fetch(&dm_address)
        .await
        .expect("data_map_fetch should succeed");

    assert_eq!(
        result.data_map.infos().len(),
        fetched_dm.infos().len(),
        "Fetched DataMap should have same number of chunks"
    );

    // Use the fetched DataMap to download the original data (retry for CI transport flakiness)
    let mut downloaded = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match client.data_download(&fetched_dm).await {
            Ok(d) => {
                downloaded = Some(d);
                break;
            }
            Err(e) if attempt < 2 => {
                eprintln!("attempt {attempt}: data_download failed: {e}");
            }
            Err(e) => panic!("data_download from fetched DataMap should succeed: {e}"),
        }
    }
    let downloaded = downloaded.expect("data_download should succeed after retries");

    assert_eq!(
        downloaded, content,
        "downloaded content should match original"
    );
}
