//! Payment verification of proofs built the client's way: each case
//! collects real quotes, tampers with the proof or the payment in one way,
//! and asserts the network refuses it. darwin-node's own tests cover
//! malformed proofs, so these are not repeated there.
//!
//! A proof that is not a proof at all (0 bytes, or random bytes) is refused
//! by darwin-node's tests, so this client no longer sends one; its
//! `test_chunk_put_with_insufficient_proof_rejected`,
//! `test_chunk_put_with_invalid_proof_rejected` and the garbage-proof half of
//! `test_payment_required_enforcement` went for them. At the revision
//! ant-core/Cargo.toml pins (81dbac7) they are the rows "0 bytes" and
//! "garbage" of the table in `test_chunk_rejected_without_payment`, in
//! `tests/e2e/data_types/chunk.rs`. A pin bump checks that they still exist at
//! the new revision (the update-ant-node-ref skill, Step 5).

use crate::support::runner::Case;
use crate::support::MiniTestnet;
use ant_core::data::{compute_address, Client, RecordWeight, SingleNodeQuotePayment};
use ant_protocol::evm::{Amount, EncodedPeerId, ProofOfPayment, RewardsAddress, TxHash};
use ant_protocol::payment::pricing::record_weight;
use ant_protocol::payment::{serialize_single_node_proof, PaymentProof};
use ant_protocol::transport::PeerId;
use ant_protocol::DATA_TYPE_CHUNK;
use bytes::Bytes;
use std::sync::Arc;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network("security::forged_signature", test_attack_forged_signature),
        Case::on_network(
            "security::wrong_chunk_address",
            test_attack_wrong_chunk_address,
        ),
        Case::on_network(
            "security::replay_to_a_different_chunk",
            test_attack_replay_different_chunk,
        ),
        Case::on_network("security::zero_amount", test_attack_zero_amount_payment),
        Case::on_network(
            "security::fabricated_tx_hash",
            test_attack_fabricated_tx_hash,
        ),
        Case::on_network(
            "security::double_spend_same_proof",
            test_attack_double_spend_same_proof,
        ),
        Case::on_network(
            "security::corrupted_public_key",
            test_attack_corrupted_public_key,
        ),
        Case::on_network(
            "security::underpayment_one_atto",
            test_attack_underpayment_single_node,
        ),
        Case::on_network(
            "security::underpayment_half_price",
            test_attack_underpayment_half_price,
        ),
    ]
}

/// Helper: collect quotes, pay on-chain, and return the raw `PaymentProof` struct,
/// the serialized proof bytes, and the target peer for PUT.
async fn collect_and_pay(client: &Client, content: &Bytes) -> (PaymentProof, Vec<u8>, PeerId) {
    let address = compute_address(content);
    let data_size = content.len() as u64;

    // Collect quotes
    let quotes = client
        .get_store_quotes(&address, data_size, 0)
        .await
        .expect("quotes should succeed");

    // Pin the first peer as the PUT target (closest from DHT)
    let target_peer = quotes.first().expect("should have quotes").0;

    // Build peer_quotes and payment
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    let mut quotes_for_payment = Vec::with_capacity(quotes.len());
    let mut commitment_sidecars = Vec::new();
    for (peer_id, _addrs, quote, _price, commitment) in quotes {
        let encoded = EncodedPeerId::new(*peer_id.as_bytes());
        peer_quotes.push((encoded, quote.clone()));
        quotes_for_payment.push(quote);
        if let Some(sidecar) = commitment {
            commitment_sidecars.push(sidecar);
        }
    }

    // Pay on-chain
    let payment = SingleNodeQuotePayment::from_quotes(quotes_for_payment, RecordWeight::FULL)
        .expect("payment creation");
    let wallet = client.wallet().expect("wallet should be set");
    let tx_hashes = payment.pay(wallet).await.expect("on-chain payment");

    // Build proof
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes,
        commitment_sidecars,
    };
    let proof_bytes = serialize_single_node_proof(&proof).expect("serialize proof");

    (proof, proof_bytes, target_peer)
}

// ─── Test 1: Forged ML-DSA-65 Signatures ────────────────────────────────────

async fn test_attack_forged_signature(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("forged signature attack test data");
    let (proof, _, target_peer) = collect_and_pay(&client, &content).await;

    // Corrupt all ML-DSA-65 signatures by flipping bytes
    let mut tampered_quotes: Vec<_> = proof.proof_of_payment.peer_quotes.clone();
    for (_encoded_peer, quote) in &mut tampered_quotes {
        for byte in &mut quote.signature {
            *byte = byte.wrapping_add(1);
        }
    }

    let tampered_proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: tampered_quotes,
        },
        tx_hashes: proof.tx_hashes.clone(),
        commitment_sidecars: proof.commitment_sidecars.clone(),
    };
    let tampered_bytes = rmp_serde::to_vec(&tampered_proof).expect("serialize tampered proof");

    let result = client
        .chunk_put_with_proof(content, tampered_bytes, &target_peer, &[])
        .await;

    assert!(
        result.is_err(),
        "PUT with forged signatures should be rejected"
    );
}

// ─── Test 2: Wrong Chunk Address ─────────────────────────────────────────────

async fn test_attack_wrong_chunk_address(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    // Get quotes and pay for chunk A
    let content_a = Bytes::from("chunk A - the one we paid for");
    let (_, proof_bytes, target_peer) = collect_and_pay(&client, &content_a).await;

    // Try to store chunk B using A's proof
    let content_b = Bytes::from("chunk B - the interloper");
    let result = client
        .chunk_put_with_proof(content_b, proof_bytes, &target_peer, &[])
        .await;

    assert!(
        result.is_err(),
        "PUT with wrong chunk address should be rejected"
    );
}

// ─── Test 3: Replay Proof for Different Chunk ────────────────────────────────

async fn test_attack_replay_different_chunk(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    // Legitimately store chunk A
    let content_a = Bytes::from("replay attack - legitimate chunk A");
    let (proof_bytes_a, peers_a) = client
        .pay_for_storage(&compute_address(&content_a), content_a.len() as u64, 0)
        .await
        .expect("payment for chunk A should succeed");
    let (target_peer_a, target_addrs_a) =
        peers_a.first().expect("should have quoted peers").clone();

    let addr_a = client
        .chunk_put_with_proof(
            content_a,
            proof_bytes_a.clone(),
            &target_peer_a,
            &target_addrs_a,
        )
        .await
        .expect("storing chunk A should succeed");

    // Verify chunk A is actually stored
    let retrieved = client.chunk_get(&addr_a).await.expect("get should succeed");
    assert!(retrieved.is_some(), "Chunk A should be stored");

    // Try to store chunk B using A's proof
    let content_b = Bytes::from("replay attack - sneaky chunk B");
    let result = client
        .chunk_put_with_proof(content_b, proof_bytes_a, &target_peer_a, &target_addrs_a)
        .await;

    assert!(
        result.is_err(),
        "Replaying chunk A's proof for chunk B should be rejected"
    );
}

// ─── Test 4: Zero-Amount Payment (Empty TX Hashes) ──────────────────────────

async fn test_attack_zero_amount_payment(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("zero amount attack test data");
    let address = compute_address(&content);
    let data_size = content.len() as u64;

    // Collect real quotes but DON'T pay on-chain
    let quotes = client
        .get_store_quotes(&address, data_size, 0)
        .await
        .expect("quotes should succeed");

    let target_peer = quotes.first().expect("should have quotes").0;
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    for (peer_id, _addrs, quote, _price, _commitment) in quotes {
        let encoded = EncodedPeerId::new(*peer_id.as_bytes());
        peer_quotes.push((encoded, quote));
    }

    // Build a proof with valid structure but empty tx_hashes
    let fake_proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes: vec![],
        commitment_sidecars: vec![],
    };
    let fake_bytes = rmp_serde::to_vec(&fake_proof).expect("serialize fake proof");

    let result = client
        .chunk_put_with_proof(content, fake_bytes, &target_peer, &[])
        .await;

    assert!(
        result.is_err(),
        "PUT with zero-amount (empty tx_hashes) should be rejected"
    );
}

// ─── Test 5: Fabricated Transaction Hash ─────────────────────────────────────

async fn test_attack_fabricated_tx_hash(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("fabricated tx hash attack test data");
    let address = compute_address(&content);
    let data_size = content.len() as u64;

    // Collect real quotes
    let quotes = client
        .get_store_quotes(&address, data_size, 0)
        .await
        .expect("quotes should succeed");

    let target_peer = quotes.first().expect("should have quotes").0;
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    for (peer_id, _addrs, quote, _price, _commitment) in quotes {
        let encoded = EncodedPeerId::new(*peer_id.as_bytes());
        peer_quotes.push((encoded, quote));
    }

    // Build proof with a fabricated tx hash (never happened on-chain)
    let fake_tx_hash = TxHash::from([0xDE; 32]);
    let fake_proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes: vec![fake_tx_hash],
        commitment_sidecars: vec![],
    };
    let fake_bytes = rmp_serde::to_vec(&fake_proof).expect("serialize fake proof");

    let result = client
        .chunk_put_with_proof(content, fake_bytes, &target_peer, &[])
        .await;

    assert!(
        result.is_err(),
        "PUT with fabricated tx hash should be rejected"
    );
}

// ─── Test 6: Double-Spend Same Proof (Idempotent) ───────────────────────────

async fn test_attack_double_spend_same_proof(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("double spend idempotency test data");
    let (_, proof_bytes, target_peer) = collect_and_pay(&client, &content).await;

    // Store chunk A successfully
    let addr1 = client
        .chunk_put_with_proof(content.clone(), proof_bytes.clone(), &target_peer, &[])
        .await
        .expect("first PUT should succeed");

    // Try to store the SAME chunk with the SAME proof again
    let addr2 = client
        .chunk_put_with_proof(content, proof_bytes, &target_peer, &[])
        .await
        .expect("second PUT (idempotent AlreadyExists) should succeed");

    assert_eq!(
        addr1, addr2,
        "Double-spend with same proof should return same address (idempotent)"
    );
}

// ─── Test 7: Corrupted Public Key ───────────────────────────────────────────

async fn test_attack_corrupted_public_key(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("corrupted public key attack test data");
    let (proof, _, target_peer) = collect_and_pay(&client, &content).await;

    // Replace all pub_key fields with random bytes
    let mut tampered_quotes: Vec<_> = proof.proof_of_payment.peer_quotes.clone();
    for (_encoded_peer, quote) in &mut tampered_quotes {
        // Replace with random garbage of the same length
        for byte in &mut quote.pub_key {
            *byte = byte.wrapping_add(0x42);
        }
    }

    let tampered_proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: tampered_quotes,
        },
        tx_hashes: proof.tx_hashes.clone(),
        commitment_sidecars: proof.commitment_sidecars.clone(),
    };
    let tampered_bytes = rmp_serde::to_vec(&tampered_proof).expect("serialize tampered proof");

    let result = client
        .chunk_put_with_proof(content, tampered_bytes, &target_peer, &[])
        .await;

    assert!(
        result.is_err(),
        "PUT with corrupted public keys should be rejected"
    );
}

// ─── Test 8: Underpayment — Single Node ─────────────────────────────────────
//
// Collects real quotes, builds a valid single-node payment, then tampers with
// the median quote's amount (reducing it to 1 atto). Pays on-chain with the
// reduced amount. The node's on-chain verifyPayment check should detect that
// the paid amount is far below the expected 3× median price and reject the PUT.

async fn test_attack_underpayment_single_node(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("underpayment attack: client pays too little");
    let address = compute_address(&content);
    let data_size = content.len() as u64;

    // 1. Collect real quotes from close group
    let quotes = client
        .get_store_quotes(&address, data_size, 0)
        .await
        .expect("quote collection should succeed");

    // Save (PeerId, RewardsAddress) mapping before consuming quotes — needed
    // to target the median peer after from_quotes() sorts internally.
    let peer_by_rewards: Vec<(PeerId, RewardsAddress)> = quotes
        .iter()
        .map(|(pid, _, q, _, _)| (*pid, q.rewards_address))
        .collect();

    // 2. Build single-node payment normally (sorts by price, median gets 3×)
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    let mut quotes_for_payment = Vec::with_capacity(quotes.len());
    let mut commitment_sidecars = Vec::new();
    for (peer_id, _addrs, quote, _price, commitment) in quotes {
        let encoded = EncodedPeerId::new(*peer_id.as_bytes());
        peer_quotes.push((encoded, quote.clone()));
        quotes_for_payment.push(quote);
        if let Some(sidecar) = commitment {
            commitment_sidecars.push(sidecar);
        }
    }

    // At the chunk's own size class, the amount a storer requires of it: a
    // full chunk's amount is several times that for a chunk this small.
    let weight = record_weight(DATA_TYPE_CHUNK, content.len());
    let mut payment = SingleNodeQuotePayment::from_quotes(quotes_for_payment, weight)
        .expect("payment creation should succeed");

    // Target the median peer specifically — it's the only one that receives
    // payment, so only it will detect the amount mismatch in verifyPayment().
    let median_quote_index = payment.quotes.len() / 2;
    let original_amount = payment.quotes[median_quote_index].amount;
    let median_rewards = payment.quotes[median_quote_index].rewards_address;
    let target_peer = peer_by_rewards
        .iter()
        .find(|(_, addr)| *addr == median_rewards)
        .expect("median rewards address must match a quoted peer")
        .0;
    assert!(
        !original_amount.is_zero(),
        "Median quote should have non-zero payment amount"
    );

    // 3. Tamper: reduce median payment to 1 atto (should be 3× median price)
    payment.quotes[median_quote_index].amount = Amount::from(1u64);

    // 4. Pay on-chain with the reduced amount — the contract records whatever
    //    amount is sent, it only validates amounts in verifyPayment()
    let wallet = client.wallet().expect("wallet should be set");
    let tx_hashes = payment
        .pay(wallet)
        .await
        .expect("on-chain payment should succeed (contract accepts any amount in payForQuotes)");

    assert!(
        !tx_hashes.is_empty(),
        "Should have at least one tx hash for the 1-atto payment"
    );

    // 5. Build proof with real ML-DSA-65 signed quotes but underpaid tx
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes,
        commitment_sidecars,
    };
    let proof_bytes = serialize_single_node_proof(&proof).expect("serialize proof");

    // 6. PUT should be REJECTED — node's verifyPayment detects 1 atto < 3× expected
    let result = client
        .chunk_put_with_proof(content, proof_bytes, &target_peer, &[])
        .await;

    assert!(
        result.is_err(),
        "PUT with underpayment (1 atto instead of {original_amount}) should be rejected"
    );
}

// ─── Test 9: Underpayment — Pay Half the Required Amount ────────────────────
//
// Verifies the boundary more closely: pays roughly half the expected 3× median
// price. The contract should still reject this because the amount is below the
// 3× threshold, even though it's not trivially small like 1 atto.

async fn test_attack_underpayment_half_price(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("half-price underpayment attack test data");
    let address = compute_address(&content);
    let data_size = content.len() as u64;

    let quotes = client
        .get_store_quotes(&address, data_size, 0)
        .await
        .expect("quote collection should succeed");

    let peer_by_rewards: Vec<(PeerId, RewardsAddress)> = quotes
        .iter()
        .map(|(pid, _, q, _, _)| (*pid, q.rewards_address))
        .collect();

    let mut peer_quotes = Vec::with_capacity(quotes.len());
    let mut quotes_for_payment = Vec::with_capacity(quotes.len());
    let mut commitment_sidecars = Vec::new();
    for (peer_id, _addrs, quote, _price, commitment) in quotes {
        let encoded = EncodedPeerId::new(*peer_id.as_bytes());
        peer_quotes.push((encoded, quote.clone()));
        quotes_for_payment.push(quote);
        if let Some(sidecar) = commitment {
            commitment_sidecars.push(sidecar);
        }
    }

    // At the chunk's own size class, the amount a storer requires of it:
    // half a full chunk's amount is more than that for a chunk this small,
    // and a storer that prices by size rightly takes it.
    let weight = record_weight(DATA_TYPE_CHUNK, content.len());
    let mut payment = SingleNodeQuotePayment::from_quotes(quotes_for_payment, weight)
        .expect("payment creation should succeed");

    // Halve the median payment (3× → ~1.5×, of the chunk's weighted price).
    // Target the median peer — only it verifies the amount it received.
    let median_quote_index = payment.quotes.len() / 2;
    let original_amount = payment.quotes[median_quote_index].amount;
    let median_rewards = payment.quotes[median_quote_index].rewards_address;
    let target_peer = peer_by_rewards
        .iter()
        .find(|(_, addr)| *addr == median_rewards)
        .expect("median rewards address must match a quoted peer")
        .0;
    let half_amount = original_amount / Amount::from(2u64);
    assert!(
        !half_amount.is_zero(),
        "Half of original amount should still be non-zero"
    );
    payment.quotes[median_quote_index].amount = half_amount;

    let wallet = client.wallet().expect("wallet should be set");
    let tx_hashes = payment
        .pay(wallet)
        .await
        .expect("on-chain payment should succeed");

    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes,
        commitment_sidecars,
    };
    let proof_bytes = serialize_single_node_proof(&proof).expect("serialize proof");

    let result = client
        .chunk_put_with_proof(content, proof_bytes, &target_peer, &[])
        .await;

    assert!(
        result.is_err(),
        "PUT with half-price payment ({half_amount} instead of {original_amount}) should be rejected"
    );
}
