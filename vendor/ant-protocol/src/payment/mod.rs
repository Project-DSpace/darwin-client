//! Wire-side payment artifacts shared by client and node.
//!
//! This module holds the types and helpers that both the client (when
//! building a payment proof for a PUT request) and the node (when
//! verifying that proof before storing a chunk) must agree on.
//!
//! The analogue in `evmlib` is the co-location of `pay` and `verify`
//! on `PaymentVault` — keeping both halves in one crate means the
//! encoding, validation, and on-chain interaction are tested end to end.

/// Signed storage-commitment type + verification shared by node and client (ADR-0004).
pub mod commitment;
/// Quadratic storage-pricing formula shared by node and client (ADR-0004).
pub mod pricing;
/// Payment proof serialization and type tagging.
pub mod proof;
/// `SingleNodePayment` construction, on-chain payment, and verification.
pub mod single_node;
/// Pure ML-DSA-65 verification helpers for quotes and merkle candidates.
pub mod verify;

pub use commitment::{
    commitment_hash, verify_commitment_signature, StorageCommitment, MAX_COMMITMENT_KEY_COUNT,
};
pub use pricing::{calculate_price, derive_records_stored_from_price};
pub use proof::{
    deserialize_merkle_proof, deserialize_proof, detect_proof_type, serialize_merkle_proof,
    serialize_single_node_proof, PaymentProof, ProofType,
};
pub use single_node::{QuotePaymentInfo, SingleNodePayment};
pub use verify::{verify_merkle_candidate_signature, verify_quote_content, verify_quote_signature};
