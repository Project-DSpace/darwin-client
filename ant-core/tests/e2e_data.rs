//! E2E tests for in-memory data with real EVM payments: content encrypted
//! in memory and stored through the raw chunk building blocks downloads and
//! range-reads, and the in-memory upload shortcuts, which store no envelope,
//! are held back.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use ant_core::data::{Client, DataMap, PaymentMode};
use bytes::Bytes;
use self_encryption::encrypt;
use self_encryption::MAX_CHUNK_SIZE;
use serial_test::serial;
use std::sync::Arc;
use support::{test_client_config, MiniTestnet, DEFAULT_NODE_COUNT};

/// Payload size that forces self-encryption to shrink the `DataMap`.
///
/// A file produces exactly 3 chunks until it exceeds `3 * MAX_CHUNK_SIZE`, and
/// self-encryption only shrinks a map with more than 3 chunk infos. Four full
/// chunks (`4 * MAX_CHUNK_SIZE`) clears that boundary regardless of the
/// configured chunk size, so the returned map has `is_child() == true`.
const SHRUNK_DATAMAP_PAYLOAD_BYTES: usize = 4 * MAX_CHUNK_SIZE;

async fn setup() -> (Client, MiniTestnet) {
    let testnet = MiniTestnet::start(DEFAULT_NODE_COUNT).await;
    let node = testnet.node(4).expect("Node 4 should exist");

    let client = Client::from_node(Arc::clone(&node), test_client_config())
        .with_wallet(testnet.wallet().clone());

    (client, testnet)
}

/// Encrypt `content` in memory and store its chunks through the raw
/// `batch_upload_chunks` building block, with no envelope, as
/// `data_upload` did before it was held back. Returns the data map and the
/// number of chunks stored.
async fn store_content(client: &Client, content: Bytes) -> (DataMap, usize) {
    let (data_map, chunks) = encrypt(content).expect("encrypt");
    let (addresses, _storage_cost, _gas_cost) = client
        .batch_upload_chunks(chunks.into_iter().map(|chunk| chunk.content).collect())
        .await
        .expect("store the chunks");
    (data_map, addresses.len())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_data_upload_download_round_trip() {
    let (client, testnet) = setup().await;

    // Self-encryption requires at least 3072 bytes
    let content = Bytes::from(vec![0x42u8; 4096]);

    let (data_map, chunks_stored) = store_content(&client, content.clone()).await;

    assert!(
        chunks_stored >= 3,
        "self-encryption produces at least 3 chunks"
    );

    let downloaded = client
        .data_download(&data_map)
        .await
        .expect("data_download should succeed");

    assert_eq!(
        downloaded, content,
        "downloaded content should match original"
    );

    let range = client
        .data_download_range(&data_map, 1020, 1500)
        .await
        .expect("shared range reader should succeed");
    assert_eq!(range, content.slice(1020..2520));
    assert!(client
        .data_download_range(&data_map, content.len(), 10)
        .await
        .unwrap()
        .is_empty());

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_data_large_content() {
    let (client, testnet) = setup().await;

    // 100KB of patterned data
    let content: Vec<u8> = (0u8..=255).cycle().take(100_000).collect();
    let content = Bytes::from(content);

    let (data_map, chunks_stored) = store_content(&client, content.clone()).await;

    assert!(chunks_stored >= 3, "should produce multiple chunks");

    let downloaded = client
        .data_download(&data_map)
        .await
        .expect("data_download should succeed");

    assert_eq!(
        downloaded.len(),
        content.len(),
        "downloaded size should match"
    );
    assert_eq!(downloaded, content, "content should match exactly");

    drop(client);
    testnet.teardown().await;
}

/// Regression test: a payload large enough to shrink the `DataMap` must still
/// round-trip through storing its chunks and `data_download`.
///
/// Before the fix, `data_download` fed the shrunk map's wrapper-level `infos()`
/// straight to `self_encryption::decrypt`, which never fetched the root content
/// chunks and failed with `Encryption("... Missing chunk ...")`. Small payloads
/// (<= 3 chunks, flat map) hid the bug because they are never shrunk.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_data_shrunk_datamap_round_trip() {
    let (client, testnet) = setup().await;

    // Patterned data so a correct round-trip must reproduce the exact bytes,
    // not merely match on length.
    let content: Vec<u8> = (0u8..=255)
        .cycle()
        .take(SHRUNK_DATAMAP_PAYLOAD_BYTES)
        .collect();
    let content = Bytes::from(content);

    let (data_map, _) = store_content(&client, content.clone()).await;

    // Guard: if this payload ever stops producing a shrunk (child) map, the
    // test would silently stop exercising the regression it protects against.
    assert!(
        data_map.is_child(),
        "payload of {} bytes should produce a shrunk (child) DataMap (infos={})",
        SHRUNK_DATAMAP_PAYLOAD_BYTES,
        data_map.infos().len()
    );

    let mut downloaded = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match client.data_download(&data_map).await {
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

    drop(client);
    testnet.teardown().await;
}

/// `data_upload` and `data_upload_with_mode` store no envelope, so they are
/// off: each refuses, naming what to use instead, and nothing is paid or
/// stored.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_data_upload_is_held_back() {
    let (client, testnet) = setup().await;

    let content = Bytes::from(vec![0x4cu8; 4096]);
    let (_, chunks) = encrypt(content.clone()).expect("encrypt");
    let balance_before = client
        .wallet()
        .expect("wallet should be set")
        .balance_of_tokens()
        .await
        .expect("balance query should succeed");

    for result in [
        client.data_upload(content.clone()).await,
        client
            .data_upload_with_mode(content.clone(), PaymentMode::Single)
            .await,
        client
            .data_upload_with_mode(content.clone(), PaymentMode::Merkle)
            .await,
    ] {
        let error = result.expect_err("held back").to_string();
        assert!(
            error.contains("data_upload is off in this build"),
            "{error}"
        );
        assert!(error.contains("file_upload"), "{error}");
        assert!(
            error.contains("data_prepare_upload_with_visibility"),
            "{error}"
        );
    }

    let balance_after = client
        .wallet()
        .expect("wallet should be set")
        .balance_of_tokens()
        .await
        .expect("balance query should succeed");
    assert_eq!(balance_before, balance_after, "nothing is paid");
    for chunk in &chunks {
        let address = ant_core::data::compute_address(&chunk.content);
        assert!(
            !client.chunk_exists(&address).await.expect("check"),
            "nothing is stored"
        );
    }

    // Content too small to encrypt (under 3 bytes) is refused before any
    // chunk exists.
    assert!(encrypt(Bytes::from(vec![0x42u8; 2])).is_err());

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_data_deterministic_encryption() {
    let (client, testnet) = setup().await;

    let content = Bytes::from(vec![0xAA; 4096]);

    let (data_map1, _) = store_content(&client, content.clone()).await;

    let (data_map2, _) = store_content(&client, content.clone()).await;

    // Verify download produces the original content (retry for CI transport flakiness)
    let mut downloaded = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match client.data_download(&data_map2).await {
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
        data_map1.infos().len(),
        data_map2.infos().len(),
        "same content should produce same number of chunks"
    );

    // Verify chunk addresses match (convergent encryption property)
    for (a, b) in data_map1.infos().iter().zip(data_map2.infos().iter()) {
        assert_eq!(
            a.dst_hash, b.dst_hash,
            "same content should produce same chunk addresses"
        );
    }

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_data_upload_partial_overlap_skips_payment_for_existing_chunks() {
    let (client, testnet) = setup().await;

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
    let (data_map, chunks_stored) = store_content(&client, content.clone()).await;

    assert!(chunks_stored >= 3, "should store at least 3 chunks total");

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
    let (_, chunks_stored2) = store_content(&client, content.clone()).await;

    assert_eq!(
        chunks_stored, chunks_stored2,
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
        match client.data_download(&data_map).await {
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

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_public_data_map_store_and_fetch() {
    let (client, testnet) = setup().await;

    // Store the content's chunks, get a DataMap
    let content = Bytes::from(vec![0xFFu8; 4096]);
    let (data_map, _) = store_content(&client, content.clone()).await;

    // Store the DataMap publicly (as a chunk on the network)
    let dm_address = client
        .data_map_store(&data_map)
        .await
        .expect("data_map_store should succeed");

    // Fetch it back by address
    let fetched_dm = client
        .data_map_fetch(&dm_address)
        .await
        .expect("data_map_fetch should succeed");

    assert_eq!(
        data_map.infos().len(),
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

    drop(client);
    testnet.teardown().await;
}
