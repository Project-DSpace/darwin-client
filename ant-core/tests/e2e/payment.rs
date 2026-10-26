//! DARWIN payments per chunk: concurrent paid uploads, a maximum-size chunk,
//! quote collection from the close group, insufficient funds, and a payment
//! made before a close-group node fails.

use crate::support::runner::Case;
use crate::support::{test_client_config, MiniTestnet, CLIENT_NODE, DEFAULT_NODE_COUNT};
use ant_core::data::{compute_address, Client};
use ant_protocol::payment::calculate_price;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network("payment::concurrent_uploads", concurrent_uploads),
        Case::on_network("payment::large_chunk", large_chunk),
        Case::on_network("payment::quote_collection", quote_collection),
        Case::on_network("payment::insufficient_funds", insufficient_funds),
        // Shuts a node down, so it runs after every other case.
        Case::on_network("payment::node_failure", node_failure).last(),
    ]
}

async fn concurrent_uploads(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content_a = Bytes::from("concurrent upload chunk A");
    let content_b = Bytes::from("concurrent upload chunk B");
    let content_c = Bytes::from("concurrent upload chunk C");

    let client_ref = &client;
    let (result_a, result_b, result_c) = futures::join!(
        client_ref.chunk_put(content_a.clone()),
        client_ref.chunk_put(content_b.clone()),
        client_ref.chunk_put(content_c.clone()),
    );

    let addr_a = result_a.expect("chunk A upload should succeed");
    let addr_b = result_b.expect("chunk B upload should succeed");
    let addr_c = result_c.expect("chunk C upload should succeed");

    for (address, content) in [
        (addr_a, &content_a),
        (addr_b, &content_b),
        (addr_c, &content_c),
    ] {
        let chunk = client
            .chunk_get(&address)
            .await
            .expect("get")
            .expect("chunk should exist");
        assert_eq!(chunk.content.as_ref(), content.as_ref());
    }

    assert_ne!(addr_a, addr_b, "A and B should have different addresses");
    assert_ne!(addr_b, addr_c, "B and C should have different addresses");
    assert_ne!(addr_a, addr_c, "A and C should have different addresses");
}

async fn large_chunk(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    // 1 MB chunk
    let large_content = Bytes::from(vec![0xAB_u8; 1_000_000]);
    let address = client
        .chunk_put(large_content.clone())
        .await
        .expect("large chunk_put should succeed");
    assert_eq!(
        address,
        compute_address(&large_content),
        "address should match BLAKE3 hash"
    );

    let chunk = client
        .chunk_get(&address)
        .await
        .expect("chunk_get should succeed")
        .expect("Large chunk should be found");
    assert_eq!(
        chunk.content.len(),
        1_000_000,
        "Retrieved chunk should be 1 MB"
    );
    assert_eq!(chunk.content.as_ref(), large_content.as_ref());
}

/// Quotes come from several distinct close-group peers, each a baseline
/// ADR-0004 quote from a node with no commitment: count 0, no pin, no
/// commitment shipped, priced at `calculate_price(0)`.
async fn quote_collection(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("quote collection test data");
    let address = compute_address(&content);
    let quotes = client
        .get_store_quotes(&address, content.len() as u64, 0)
        .await
        .expect("get_store_quotes should succeed");

    // A healthy network should still return several quotes even though the
    // degraded single-node path can proceed with only one.
    assert!(
        quotes.len() >= 5,
        "Should receive at least 5 quotes, got {}",
        quotes.len()
    );

    let baseline = calculate_price(0);
    for (peer_id, _addrs, quote, price, commitment) in &quotes {
        assert!(
            !price.is_zero(),
            "Quote price from peer {peer_id} should be > 0"
        );
        assert_eq!(
            quote.committed_key_count, 0,
            "no-commitment node must quote count 0 ({peer_id})"
        );
        assert!(
            quote.commitment_pin.is_none(),
            "baseline quote pins nothing ({peer_id})"
        );
        assert_eq!(
            quote.price, baseline,
            "baseline quote must price at calculate_price(0) ({peer_id})"
        );
        assert!(
            commitment.is_none(),
            "baseline quote ships no commitment ({peer_id})"
        );
    }

    let unique_peers: std::collections::HashSet<_> =
        quotes.iter().map(|(p, _, _, _, _)| *p).collect();
    assert_eq!(
        unique_peers.len(),
        quotes.len(),
        "All quote peer IDs should be unique"
    );
}

async fn insufficient_funds(testnet: Arc<MiniTestnet>) {
    let node = testnet.node(CLIENT_NODE).expect("client node");

    // A wallet with zero balance (not the Anvil-funded default key).
    let empty_wallet = ant_protocol::evm::Wallet::new_from_private_key(
        testnet.evm_network().clone(),
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    )
    .expect("create wallet from random key");
    let client = Client::from_node(node, test_client_config()).with_wallet(empty_wallet);

    let result = client
        .chunk_put(Bytes::from("insufficient funds test data"))
        .await;
    assert!(
        result.is_err(),
        "chunk_put should fail with an unfunded wallet"
    );
}

/// A chunk stored before a node fails still reads back after it.
async fn node_failure(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("resilience test: payment before node failure");
    let stored_address = client
        .chunk_put(content.clone())
        .await
        .expect("initial chunk_put should succeed");

    testnet.shutdown_node(5).await;
    assert_eq!(
        testnet.running_node_count(),
        DEFAULT_NODE_COUNT - 1,
        "Should have one fewer node after shutting down 1"
    );

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Retry to let the network settle.
    let mut chunk = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        match client.chunk_get(&stored_address).await {
            Ok(Some(c)) => {
                chunk = Some(c);
                break;
            }
            Ok(None) => eprintln!("attempt {attempt}: chunk_get returned None"),
            Err(e) => eprintln!("attempt {attempt}: chunk_get failed: {e}"),
        }
    }
    let chunk = chunk.expect("Chunk should be retrievable after node failure");
    assert_eq!(chunk.content.as_ref(), content.as_ref());
}
