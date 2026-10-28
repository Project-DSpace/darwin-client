//! ADR-0004 end-to-end: commitment-bound quote pricing.
//!
//! Proves, against a real in-process QUIC testnet + Anvil EVM, that:
//!
//! 1. A node carrying a live storage commitment emits a COMMITMENT-BOUND quote:
//!    `committed_key_count == N`, `commitment_pin == Some`, the price is exactly
//!    `calculate_price(N)`, and the signed commitment is SHIPPED in the quote
//!    response (ADR-0004 "the commitment arrived with the quote").
//! 2. The client's forced-price gate ACCEPTS those bound quotes (they are
//!    self-consistent) and a full pay → store → retrieve round-trip succeeds —
//!    so the storer accepts the bound quotes and the forwarded sidecars too.
//! 3. A forced-merkle upload on the commitment-bound network is refused at
//!    quote time with nothing paid, as darwin-node refuses every batch payment.
//!
//! Both run on the committed network: every node carries a live commitment
//! over [`COMMITTED_KEYS`] keys. The baseline branch of the same gate (a node
//! with no commitment quotes `(0, None)` at `calculate_price(0)`) is pinned
//! by `payment::quote_collection` on the shared network, where every other
//! case pays, stores and reads back on baseline quotes.
//!
//! The OFF-CURVE rejection (a node charging above its committed count is dropped
//! before payment) is proven directly on the gate in the `quote.rs` unit tests
//! (`classifier_drops_off_curve_quote_with_typed_error` + the
//! `quote_commitment_binding_is_valid` suite) — honest nodes never emit an
//! off-curve quote, so it cannot be surfaced through a live happy-path network.

use crate::merkle::merkle_client;
use crate::support::runner::{Case, COMMITTED_KEYS};
use crate::support::{assert_batch_refused, wallet_spend, MiniTestnet};
use ant_core::data::client::merkle::PaymentMode;
use ant_core::data::compute_address;
use ant_node::payment::pricing::quote_price_at;
use ant_protocol::payment::commitment::{
    commitment_hash, verify_commitment_signature, StorageCommitment,
};
use bytes::Bytes;
use std::io::Write;
use std::sync::Arc;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_committed(
            "adr0004::bound_quotes_are_shipped_priced_and_resolve",
            adr0004_bound_quotes_are_shipped_priced_and_resolve,
        ),
        Case::on_committed(
            "adr0004::merkle_upload_against_bound_candidates_is_refused",
            adr0004_merkle_upload_against_bound_candidates_is_refused,
        ),
    ]
}

async fn adr0004_bound_quotes_are_shipped_priced_and_resolve(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("adr-0004 bound-quote payload");
    let address = compute_address(&content);

    // Collect quotes directly so we can inspect the ADR-0004 binding the client
    // verified before it would pay.
    let quotes = client
        .get_store_quotes(&address, content.len() as u64, 0)
        .await
        .expect("quote collection should reach quorum");

    assert!(
        quotes.len() >= ant_protocol::CLOSE_GROUP_SIZE,
        "must collect a full close group of bound quotes, got {}",
        quotes.len()
    );

    for (peer_id, _addrs, quote, price, commitment) in &quotes {
        // The node prices on the curve of the quote's own signing time: the
        // earlier x32 curve before its PRICE_SWITCH_AT, the new one from it.
        let expected_price = quote_price_at(COMMITTED_KEYS as usize, quote.timestamp);
        // Bound shape: the count is what the node committed, with a pin.
        assert_eq!(
            quote.committed_key_count, COMMITTED_KEYS,
            "quote from {peer_id} must carry the committed key count"
        );
        let pin = quote
            .commitment_pin
            .expect("a bound quote must carry a commitment pin");

        // Forced price: exactly calculate_price(N), by recomputation. This is
        // the ceiling — a node cannot charge above what it can prove it stores.
        assert_eq!(
            quote.price, expected_price,
            "quote from {peer_id} must be priced on its curve at the committed key count"
        );
        assert_eq!(*price, expected_price);

        // The commitment arrived WITH the quote (no separate fetch needed).
        let sidecar = commitment
            .as_ref()
            .expect("a bound quote response must ship its signed commitment");

        // FULLY resolve the shipped commitment exactly as the client gate does
        // before paying — this is the real anti-cheat invariant, not just
        // "non-empty bytes". The commitment must deserialize, carry a valid
        // signature, be bound to the quoting peer, hash to the quote's pin, and
        // attest exactly the claimed count.
        let resolved: StorageCommitment =
            rmp_serde::from_slice(sidecar).expect("shipped commitment must deserialize");
        assert!(
            verify_commitment_signature(&resolved),
            "shipped commitment from {peer_id} must be validly signed"
        );
        assert_eq!(
            resolved.sender_peer_id,
            *peer_id.as_bytes(),
            "shipped commitment must be bound to the quoting peer"
        );
        assert_eq!(
            compute_address(&resolved.sender_public_key),
            *peer_id.as_bytes(),
            "BLAKE3(sender_public_key) must equal the quoting peer (full peer binding)"
        );
        assert_eq!(
            commitment_hash(&resolved),
            Some(pin),
            "shipped commitment must hash to the quote's pin"
        );
        assert_eq!(
            resolved.key_count, COMMITTED_KEYS,
            "shipped commitment must attest exactly the committed key count"
        );
    }

    // Full round-trip: the client paid (accepting the bound quotes + forwarding
    // the sidecars), the storers accepted the bundle, and the chunk is back.
    let stored = client
        .chunk_put(content.clone())
        .await
        .expect("paid put with commitment-bound quotes must succeed");
    assert_eq!(stored, address);

    let retrieved = client
        .chunk_get(&address)
        .await
        .expect("chunk_get should succeed")
        .expect("chunk must be found after storing");
    assert_eq!(retrieved.content.as_ref(), content.as_ref());
}

/// A FORCED-MERKLE upload against a network where every node carries a live
/// storage commitment (bound candidates) is refused at quote time, before any
/// candidate's binding is checked or anything is paid: darwin-node refuses
/// batch payments. Against upstream's nodes this case was the DEV-01
/// regression (bound candidates broke merkle uploads the moment nodes rotated
/// their first commitment, 2026-07-06 19:38 UTC); here it pins that a
/// commitment-bound network refuses batches as an unbound one does, and that
/// per-chunk payment, which the first test in this file pins, still works.
async fn adr0004_merkle_upload_against_bound_candidates_is_refused(testnet: Arc<MiniTestnet>) {
    // Enough nodes that the client asks them for candidates at all.
    let client = merkle_client(&testnet);

    // 500KB file — self-encryption produces 3+ chunks (>=2 needed for merkle).
    let data: Vec<u8> = (0u8..=255).cycle().take(500_000).collect();
    let mut input_file = tempfile::NamedTempFile::new().expect("create temp file");
    input_file.write_all(&data).expect("write temp file");
    input_file.flush().expect("flush temp file");

    let before = wallet_spend(testnet.wallet()).await;
    let error = client
        .file_upload_with_mode(input_file.path(), PaymentMode::Merkle)
        .await
        .expect_err("darwin-node refuses batch payments, bound candidates or not");
    assert_batch_refused(&error);
    assert_eq!(
        wallet_spend(testnet.wallet()).await,
        before,
        "nothing may be paid for a refused batch"
    );
}
