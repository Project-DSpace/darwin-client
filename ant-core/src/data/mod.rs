//! Data operations for the Autonomi decentralized network.
//!
//! Provides high-level APIs for storing and retrieving data
//! using post-quantum cryptography.

pub mod client;
pub mod error;
pub mod network;
#[cfg(feature = "native")]
pub mod peer_cache;

#[cfg(feature = "native")]
pub use ant_listings::WalkOutcome;
pub use client::cache::ChunkCache;
#[cfg(feature = "native")]
pub use client::listings::{
    expected_nearest, paid_quote_hash, walk_start, Carry, CheckedListing, ListingChain,
    ListingLookup, ListingsIndex, RejectedListing, WalkReport, WalkState, NEAREST_NODES,
};
pub use client::{Client, ClientConfig};
pub use error::{Error, Result};
pub use network::{Network, NetworkHealth, REBOOTSTRAP_THRESHOLD};

// LocalDevnet (and the optional node-side dep it pulls in) is gated behind
// the `devnet` feature. Default builds of ant-core do not link ant-node.
#[cfg(feature = "devnet")]
pub use crate::node::devnet::LocalDevnet;

// Re-export commonly used types from the wire protocol crate.
pub use ant_protocol::{compute_address, DataChunk, XorName};

// The pointer record (ADR-0016) and the owner key that signs it, so a caller of
// the pointer API needs no direct protocol dependency.
pub use ant_protocol::pointer::{pointer_address, Pointer, PointerTarget, PointerTargetKind};
pub use ant_protocol::pqc::api::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

// Re-export client data types
pub use client::batch::{
    finalize_batch_payment, ChunkPaymentPlan, PaidChunk, PaymentIntent, PreparedChunk,
    SingleNodeQuotePayment,
};
pub use client::data::DataUploadResult;
#[cfg(feature = "native")]
pub use client::diagnostics::{
    spawn_download_diagnostics_writer, DownloadDiagnosticsOutcome, DownloadDiagnosticsRecord,
    DownloadDiagnosticsSender,
};
pub use client::envelope::{
    proof_data_map, shown_after_hiding, EnvelopeOptions, EnvelopeWarning, Extent, UploadEnvelope,
};
#[cfg(feature = "native")]
pub use client::file::{
    file_data_map, forget_upload_record, ExternalChunkStore, ExternalPaymentInfo, FinalizeOutcome,
    FinalizeResume, MerkleFinalizeResume, PreparedUpload, UploadPayer, WaveFinalizeResume,
};
pub use client::file::{
    CostEstimateConfidence, DownloadEvent, FileChunkPeerReport, FileChunkPeerReportPeer,
    FileChunkPeerStatus, FileChunkPeerSweepReport, FileDownloadWithPeerReport, FileUploadResult,
    UploadCostEstimate, UploadEvent, Visibility,
};
pub use client::merkle::{
    finalize_merkle_batch, MerkleBatchPaymentResult, PaymentMode, PreparedMerkleBatch,
    DEFAULT_MERKLE_THRESHOLD,
};
pub use client::upload::{MerkleUploadPayment, UploadPayment};

// Re-export self-encryption types
pub use self_encryption::DataMap;

// Datamap file persistence helpers. Canonical path is
// `ant_core::datamap_file::*`; these convenience re-exports let existing
// `ant_core::data` callers reach them without an extra import.
#[cfg(feature = "native")]
pub use crate::datamap_file::{
    datamap_filename_for, original_name_from_datamap, read_datamap, write_datamap, CollisionPolicy,
    DATAMAP_EXTENSION,
};

// Re-export networking types needed by CLI for P2P node creation. The
// devnet manifest types live in ant-protocol because both the node
// (writer) and the CLI (reader) need them; they are always available
// regardless of the `devnet` feature.
#[cfg(feature = "native")]
pub use ant_protocol::transport::{
    CoreNodeConfig, IPDiversityConfig, MultiAddr, NodeMode, P2PNode,
};
pub use ant_protocol::{DevnetManifest, MAX_CHUNK_SIZE, MAX_WIRE_MESSAGE_SIZE};

// Re-export EVM types needed by CLI for wallet and network setup
pub use ant_protocol::evm::{
    Address as EvmAddress, CustomNetwork, Network as EvmNetwork, Wallet, U256,
};
