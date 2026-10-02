//! # ant-protocol
//!
//! Wire protocol for the Autonomi decentralized network (`WithAutonomi` fork).
//!
//! This crate is the contract between `ant-client` and `ant-node`:
//! wire message types, serialization, content addressing, and the
//! pure-verification halves of the post-quantum signing scheme. Both
//! crates depend on `ant-protocol` and on nothing else from each other.
//!
//! ## Scope
//!
//! - [`chunk`] — chunk request/response messages, protocol constants,
//!   `ProtocolError`, close-group sizing, proof-type tag bytes.
//! - [`data_types`] — pure helpers on 32-byte addresses (`compute_address`,
//!   `xor_distance`, `peer_id_to_xor_name`) and `DataChunk`.
//! - [`chunk_protocol`] — a shared "subscribe → send → poll" helper
//!   [`chunk_protocol::send_and_await_chunk_response`] that both the
//!   client and node test harness use to exchange chunk messages on
//!   a `saorsa-core::P2PNode`.
//! - [`payment`] — on-wire payment artifacts: `PaymentProof`,
//!   `SingleNodePayment` (with `pay` and `verify` co-located), and
//!   ML-DSA-65 verification of quotes and merkle candidates.
//!
//! ## What is **not** here
//!
//! - Quote generation and node-side signing keys (stay in `ant-node`).
//! - On-chain verification cache and payment verifier state machine
//!   (stay in `ant-node`).
//! - `LocalDevnet` and node process management (stay in `ant-client`
//!   and `ant-node` respectively).
//!
//! ## Logging
//!
//! The `logging` feature re-exports [`tracing`] macros. When disabled
//! the macros become no-ops with zero runtime cost.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
// Variables used only inside log macros become unused when `logging` is off.
#![cfg_attr(not(feature = "logging"), allow(unused_variables, unused_assignments))]

pub mod chunk;
#[cfg(feature = "native")]
pub mod chunk_protocol;
pub mod data_types;
pub mod devnet_manifest;
pub mod error;
pub mod logging;
pub mod payment;
pub mod pointer;

// =============================================================================
// Public surface re-exports
// =============================================================================

pub use chunk::{
    client_update_required_message, settlement_compatibility, ChunkGetRequest, ChunkGetResponse,
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteRequestV2, ChunkQuoteResponse, MerkleCandidateQuoteRequest,
    MerkleCandidateQuoteRequestV2, MerkleCandidateQuoteResponse, PointerGetRequest,
    PointerGetResponse, PointerPutRequest, PointerPutResponse, ProtocolError,
    SettlementCompatibility, XorName, CHUNK_PROTOCOL_ID, CLOSE_GROUP_MAJORITY, CLOSE_GROUP_SIZE,
    CURRENT_SETTLEMENT_VERSION, DATA_TYPE_CHUNK, MAX_CHUNK_SIZE, MAX_WIRE_MESSAGE_SIZE,
    MIN_SUPPORTED_SETTLEMENT_VERSION, PROOF_TAG_MERKLE, PROOF_TAG_SINGLE_NODE, PROTOCOL_VERSION,
    XORNAME_LEN,
};
#[cfg(feature = "native")]
pub use chunk_protocol::{
    send_and_await_chunk_response, send_and_await_chunk_response_with_metadata,
    ChunkProtocolResponse,
};
pub use data_types::{compute_address, peer_id_to_xor_name, xor_distance, ChunkStats, DataChunk};
pub use devnet_manifest::{DevnetEvmInfo, DevnetManifest};
pub use error::{Error, Result};
pub use payment::{
    deserialize_merkle_proof, deserialize_proof, detect_proof_type, serialize_merkle_proof,
    serialize_single_node_proof, verify_merkle_candidate_signature, verify_quote_content,
    verify_quote_signature, PaymentProof, ProofType, QuotePaymentInfo, SingleNodePayment,
};
pub use pointer::{
    pointer_address, state_id_for_body, ParsedPointer, Pointer, PointerError, PointerState,
    PointerTarget, PointerTargetKind, DATA_TYPE_POINTER, POINTER_BODY_LEN, POINTER_FORMAT_VERSION,
    POINTER_WIRE_LEN, TARGET_WIRE_LEN,
};

// =============================================================================
// Transitive-dep re-exports
//
// `ant-client` and `ant-node` must compile against the *same* major version
// of `evmlib`, `saorsa-core`, and `saorsa-pqc`. Re-exporting them here makes
// `ant-protocol` the single version-pin point: bump the version here and
// both sides move together. Adding a direct dependency on any of these
// crates in `ant-client` risks a silent version skew that only manifests
// at runtime (different `ProofOfPayment` layout, incompatible `P2PNode`
// behaviours, etc.).
//
// These modules hold only `pub use` — no code of our own. They exist as
// a policy gate, not an abstraction.
// =============================================================================

/// EVM payment primitives re-exported from [`evmlib`].
///
/// Use `ant_protocol::evm::…` in downstream crates instead of a direct
/// `evmlib` dependency. This guarantees client and node always link the
/// same `evmlib` major version.
pub mod evm {
    pub use evmlib::common::{Address, Amount, QuoteHash, TxHash, U256};
    pub use evmlib::merkle_batch_payment::PoolCommitment;
    pub use evmlib::merkle_payments::{
        MerklePaymentCandidateNode, MerklePaymentCandidatePool, MerklePaymentProof,
        MerklePaymentVerificationError, MerkleTree, MidpointProof, CANDIDATES_PER_POOL, MAX_LEAVES,
        MERKLE_PAYMENT_EXPIRATION,
    };
    #[cfg(feature = "native")]
    pub use evmlib::wallet::journal;
    #[cfg(feature = "rpc")]
    pub use evmlib::wallet::{PayForQuotesError, Wallet};
    pub use evmlib::{
        CustomNetwork, EncodedPeerId, Network, PaymentQuote, ProofOfPayment, RewardsAddress,
    };

    /// Anvil-backed testnet used by devnets and E2E tests.
    ///
    /// Exposed so downstream `LocalDevnet` wrappers and test harnesses
    /// don't need a direct `evmlib` dep just for the Anvil bindings.
    #[cfg(feature = "native")]
    pub mod testnet {
        pub use evmlib::testnet::Testnet;
    }

    /// Lower-level `evmlib` surface (RPC provider, contract interface,
    /// and payment-vault bindings). Re-exported for the node's verifier
    /// and the Anvil-based tests; most client code will not need these.
    #[cfg(feature = "rpc")]
    pub mod contract {
        pub use evmlib::contract::payment_vault;
    }

    /// HTTP provider + transaction-config helpers used by on-chain
    /// verification flows.
    #[cfg(feature = "rpc")]
    pub mod utils {
        pub use evmlib::transaction_config::TransactionConfig;
        pub use evmlib::utils::{dummy_address, dummy_hash, http_provider};
    }
}

/// Saorsa transport primitives re-exported from [`saorsa_core`].
///
/// Use `ant_protocol::transport::…` in downstream crates instead of a
/// direct `saorsa-core` dependency.
pub mod transport {
    /// Browser RPC capability requiring owner-signed V2 address records.
    /// This does not select native DHT protocols; native peers send both versions.
    pub const ADDRESS_V2_CAPABILITY: &str = "addr-v2";

    pub use saorsa_core::client_routing;
    pub use saorsa_core::dht_lookup::{
        DEFAULT_ALPHA_VALUE, DEFAULT_K_VALUE, ITERATION_GRACE_TIMEOUT_SECS, LOOKUP_TIMEOUT_SECS,
    };
    pub use saorsa_core::identity::{NodeIdentity, PeerId};
    pub use saorsa_core::signed_address;
    pub use saorsa_core::{
        collect_after_first_with_grace, run_iterative_lookup, xor_distance, AddressType, DHTNode,
        IterativeLookup, KnownReachability, LookupConfig, LookupKey, LookupNode, LookupQuery,
        LookupQueryOutcome, LookupRunError, LookupTermination, MlDsa65, MultiAddr, ResponderView,
        TransportAddressRecord, WitnessedCloseGroup,
    };
    #[cfg(feature = "native")]
    pub use saorsa_core::{
        IPDiversityConfig, NodeConfig as CoreNodeConfig, NodeMode, P2PEvent, P2PNode, PeerRouteKind,
    };
}

/// Post-quantum crypto primitives re-exported from [`saorsa_pqc`].
///
/// Both API paths are re-exported:
/// - `ant_protocol::pqc::ops::*` (lower-level `pqc::*` module) — used
///   by the node and by this crate's own verification code.
/// - `ant_protocol::pqc::api::*` (higher-level `api::sig::*` module) —
///   used by the client's binary-update signature verification.
pub mod pqc {
    /// Lower-level `pqc::*` API (types + `MlDsaOperations` trait).
    pub mod ops {
        pub use saorsa_pqc::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
        pub use saorsa_pqc::pqc::MlDsaOperations;
    }

    /// Higher-level `api::sig::*` API (used for release signatures).
    pub mod api {
        pub use saorsa_pqc::api::sig::{
            ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
        };
    }
}
