//! Pure verification helpers for payment quotes and merkle candidates.
//!
//! These functions inspect signed wire artifacts (`PaymentQuote` and
//! `MerklePaymentCandidateNode`) and confirm their ML-DSA-65 signatures
//! are valid. They do no I/O and do not touch on-chain state.
//!
//! Both the client (when building proofs) and the node (when validating
//! incoming PUTs) need identical verification semantics — keeping these
//! functions in `ant-protocol` ensures the client and node cannot drift.

use crate::chunk::XorName;
use crate::logging::debug;
use evmlib::merkle_payments::MerklePaymentCandidateNode;
use evmlib::PaymentQuote;
use saorsa_pqc::pqc::types::{MlDsaPublicKey, MlDsaSignature};
use saorsa_pqc::pqc::MlDsaOperations;
use saorsa_pqc::MlDsa65;

/// Verify that a payment quote's content address matches the expected address.
///
/// This is a pure field-equality check — the signature is verified
/// separately via [`verify_quote_signature`].
///
/// # Arguments
///
/// * `quote` - The quote to check.
/// * `expected_content` - The address the caller expected.
///
/// # Returns
///
/// `true` if `quote.content` equals `expected_content`.
#[must_use]
pub fn verify_quote_content(quote: &PaymentQuote, expected_content: &XorName) -> bool {
    if quote.content.0 != *expected_content {
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            debug!(
                "Quote content mismatch: expected {}, got {}",
                hex::encode(expected_content),
                hex::encode(quote.content.0)
            );
        }
        return false;
    }
    true
}

/// Verify a payment quote's ML-DSA-65 signature.
///
/// Autonomi uses ML-DSA-65 post-quantum signatures for quote signing
/// (not the Ed25519/libp2p signatures that the upstream `ant-evm`
/// library assumes). The `pub_key` field holds the raw ML-DSA-65 public
/// key bytes; `signature` is the ML-DSA-65 signature over the quote's
/// canonical signing payload (`PaymentQuote::bytes_for_sig`).
///
/// # Returns
///
/// `true` if the signature is valid for `quote.bytes_for_sig()`.
#[must_use]
pub fn verify_quote_signature(quote: &PaymentQuote) -> bool {
    let pub_key = match MlDsaPublicKey::from_bytes(&quote.pub_key) {
        Ok(pk) => pk,
        Err(e) => {
            debug!("Failed to parse ML-DSA-65 public key from quote: {e}");
            return false;
        }
    };

    let signature = match MlDsaSignature::from_bytes(&quote.signature) {
        Ok(sig) => sig,
        Err(e) => {
            debug!("Failed to parse ML-DSA-65 signature from quote: {e}");
            return false;
        }
    };

    let bytes = quote.bytes_for_sig();

    let ml_dsa = MlDsa65::new();
    match ml_dsa.verify(&pub_key, &bytes, &signature) {
        Ok(valid) => {
            if !valid {
                debug!("ML-DSA-65 quote signature verification failed");
            }
            valid
        }
        Err(e) => {
            debug!("ML-DSA-65 verification error: {e}");
            false
        }
    }
}

/// Verify a `MerklePaymentCandidateNode`'s ML-DSA-65 signature.
///
/// Autonomi uses ML-DSA-65 for merkle candidate signing; the upstream
/// `MerklePaymentCandidateNode::verify_signature()` method expects libp2p
/// Ed25519 keys and cannot be used.
///
/// `pub_key` holds the raw ML-DSA-65 public key bytes; `signature` is
/// the ML-DSA-65 signature over `MerklePaymentCandidateNode::bytes_to_sign()`.
#[must_use]
pub fn verify_merkle_candidate_signature(candidate: &MerklePaymentCandidateNode) -> bool {
    let pub_key = match MlDsaPublicKey::from_bytes(&candidate.pub_key) {
        Ok(pk) => pk,
        Err(e) => {
            debug!("Failed to parse ML-DSA-65 public key from merkle candidate: {e}");
            return false;
        }
    };

    let signature = match MlDsaSignature::from_bytes(&candidate.signature) {
        Ok(sig) => sig,
        Err(e) => {
            debug!("Failed to parse ML-DSA-65 signature from merkle candidate: {e}");
            return false;
        }
    };

    // ADR-0004: the per-node signature now covers the commitment binding
    // (`committed_key_count`, `commitment_pin`) too, so a count/pin mismatch is
    // genuine same-key-signed evidence. Must match `bytes_to_sign` in evmlib.
    let msg = MerklePaymentCandidateNode::bytes_to_sign(
        &candidate.price,
        &candidate.reward_address,
        candidate.merkle_payment_timestamp,
        candidate.committed_key_count,
        &candidate.commitment_pin,
    );

    let ml_dsa = MlDsa65::new();
    match ml_dsa.verify(&pub_key, &msg, &signature) {
        Ok(valid) => {
            if !valid {
                debug!("ML-DSA-65 merkle candidate signature verification failed");
            }
            valid
        }
        Err(e) => {
            debug!("ML-DSA-65 merkle candidate verification error: {e}");
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use evmlib::common::Amount;
    use evmlib::RewardsAddress;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;
    use std::time::SystemTime;

    fn real_ml_dsa_quote() -> (PaymentQuote, [u8; 32]) {
        let content = [7u8; 32];
        let ml_dsa = MlDsa65::new();
        let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keypair");
        let pub_key_bytes = pub_key.as_bytes().to_vec();

        // Build a quote with all fields except signature, then sign bytes_for_sig().
        let mut quote = PaymentQuote {
            content: xor_name::XorName(content),
            timestamp: SystemTime::now(),
            price: Amount::from(42u64),
            rewards_address: RewardsAddress::new([2u8; 20]),
            pub_key: pub_key_bytes,
            signature: vec![],
            committed_key_count: 0,
            commitment_pin: None,
        };
        let msg = quote.bytes_for_sig();
        let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
        let sig = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();
        quote.signature = sig;

        (quote, content)
    }

    #[test]
    fn verify_quote_content_matches() {
        let (quote, content) = real_ml_dsa_quote();
        assert!(verify_quote_content(&quote, &content));
    }

    #[test]
    fn verify_quote_content_mismatch() {
        let (quote, _) = real_ml_dsa_quote();
        let wrong = [0xFFu8; 32];
        assert!(!verify_quote_content(&quote, &wrong));
    }

    #[test]
    fn verify_quote_signature_real_keys_roundtrip() {
        let (quote, _) = real_ml_dsa_quote();
        assert!(verify_quote_signature(&quote));
    }

    #[test]
    fn verify_quote_signature_tampered_signature_fails() {
        let (mut quote, _) = real_ml_dsa_quote();
        if let Some(byte) = quote.signature.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(!verify_quote_signature(&quote));
    }

    #[test]
    fn verify_quote_signature_empty_pub_key_fails() {
        let quote = PaymentQuote {
            content: xor_name::XorName([0u8; 32]),
            timestamp: SystemTime::now(),
            price: Amount::from(1u64),
            rewards_address: RewardsAddress::new([0u8; 20]),
            pub_key: vec![],
            signature: vec![],
            committed_key_count: 0,
            commitment_pin: None,
        };
        assert!(!verify_quote_signature(&quote));
    }

    #[test]
    fn verify_quote_signature_empty_signature_fails() {
        let ml_dsa = MlDsa65::new();
        let (pub_key, _sk) = ml_dsa.generate_keypair().expect("keypair");
        let quote = PaymentQuote {
            content: xor_name::XorName([0u8; 32]),
            timestamp: SystemTime::now(),
            price: Amount::from(1u64),
            rewards_address: RewardsAddress::new([0u8; 20]),
            pub_key: pub_key.as_bytes().to_vec(),
            signature: vec![],
            committed_key_count: 0,
            commitment_pin: None,
        };
        assert!(!verify_quote_signature(&quote));
    }

    fn real_ml_dsa_merkle_candidate() -> MerklePaymentCandidateNode {
        let ml_dsa = MlDsa65::new();
        let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keypair");
        let price = Amount::from(1024u64);
        let reward_address = RewardsAddress::new([3u8; 20]);
        let merkle_payment_timestamp = 1_700_000_000u64;
        let committed_key_count = 7u32;
        let commitment_pin = Some([5u8; 32]);
        let msg = MerklePaymentCandidateNode::bytes_to_sign(
            &price,
            &reward_address,
            merkle_payment_timestamp,
            committed_key_count,
            &commitment_pin,
        );
        let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
        let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();
        MerklePaymentCandidateNode {
            pub_key: pub_key.as_bytes().to_vec(),
            price,
            reward_address,
            merkle_payment_timestamp,
            committed_key_count,
            commitment_pin,
            signature,
        }
    }

    #[test]
    fn verify_merkle_candidate_real_keys_roundtrip() {
        let candidate = real_ml_dsa_merkle_candidate();
        assert!(verify_merkle_candidate_signature(&candidate));
    }

    #[test]
    fn verify_merkle_candidate_tampered_fails() {
        let mut candidate = real_ml_dsa_merkle_candidate();
        if let Some(byte) = candidate.signature.first_mut() {
            *byte ^= 0x55;
        }
        assert!(!verify_merkle_candidate_signature(&candidate));
    }

    #[test]
    fn verify_merkle_candidate_empty_pub_key_fails() {
        let mut candidate = real_ml_dsa_merkle_candidate();
        candidate.pub_key = vec![];
        assert!(!verify_merkle_candidate_signature(&candidate));
    }

    #[test]
    fn verify_merkle_candidate_wrong_timestamp_fails() {
        let mut candidate = real_ml_dsa_merkle_candidate();
        candidate.merkle_payment_timestamp = candidate.merkle_payment_timestamp.wrapping_add(1);
        assert!(!verify_merkle_candidate_signature(&candidate));
    }
}
