//! Data operations for the Autonomi decentralized network.
//!
//! Provides high-level APIs for storing and retrieving data
//! using post-quantum cryptography.

pub mod client;
pub mod error;
pub mod manifest;
pub mod network;
#[cfg(feature = "native")]
pub mod peer_cache;

#[cfg(feature = "native")]
pub use ant_listings::WalkOutcome;
pub use client::cache::ChunkCache;
#[cfg(feature = "native")]
pub use client::listings::{
    expected_nearest, paid_quote_hash, walk_start, Carry, CheckedListing, ListingChain,
    ListingLookup, ListingsIndex, PendingCopy, RejectedListing, WalkReport, WalkState,
    NEAREST_NODES,
};
#[cfg(feature = "native")]
pub use client::listings_census::{Census, CensusNode};
#[cfg(feature = "native")]
pub use client::listings_publish::{Publication, Published, Publisher};
#[cfg(feature = "native")]
pub use client::listings_serve::{CycleReport, Producer, ServeOptions};
#[cfg(feature = "native")]
pub use client::listings_store::ListingsStore;
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
pub use ant_protocol::pointer::{
    pointer_address, Pointer, PointerTarget, PointerTargetKind, FINAL_COUNTER,
};
pub use ant_protocol::pqc::api::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

// A record's weight by its size class, which a single-node payment is planned
// for ([`SingleNodeQuotePayment::from_quotes`]).
pub use ant_protocol::payment::pricing::{record_weight, RecordWeight};

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
    BATCH_PAYMENTS_REFUSED, DEFAULT_MERKLE_THRESHOLD,
};
pub use client::occupied::{OccupiedQuote, VaultRecord, MAX_OCCUPIED_REQUOTES, QUOTES_OCCUPIED};
pub use client::pointer::{
    FinalState, FinalityStatus, PointerController, PointerFinality, PointerTransfer, SeedState,
    SeedsView,
};
pub use client::upload::{MerkleUploadPayment, UploadPayment};
#[cfg(feature = "native")]
pub use client::upload_checkpoint::{
    upload_checkpoint_files, UploadCheckpointFiles, UPLOAD_CHECKPOINT_EXTENSIONS,
};

// Re-export self-encryption types
pub use self_encryption::DataMap;

// File manifests and `darwin://` links (ADR-0006).
#[cfg(feature = "native")]
pub use manifest::{
    build::{
        BuildEvent, BuildOptions, BuildResult, ManifestBuilder, ReferenceMode, UploadedEnvelope,
    },
    compact::{
        apply_compaction, plan_compaction, publish_data_maps, CompactPlan, EmbeddedEntry,
        PublicForm,
    },
    embed::embeddable_data_map,
    extract::{
        extract_manifest, select_entries, EntryOutcome, EntryStatus, ExtractEvent, ExtractOptions,
        ExtractReport,
    },
    file::{manifest_filename_for, read_manifest_file, write_manifest_file},
    history::{
        default_history_dir, format_timestamp, list_uploads, load_upload, record_upload,
        UploadListing, UploadRecord, UPLOAD_HISTORY_DIR,
    },
};
pub use manifest::{
    data_map_address, embedded_len, file_link, is_link, manifest_link, manifest_link_bytes,
    manifest_link_from_bytes, parse_link, published_data_map, ContentRef, Link, Manifest,
    ManifestEntry, ManifestError, TorrentReference, MANIFEST_EXTENSION,
    MANIFEST_LINK_RECOMMENDED_MAX_BYTES, MAX_EMBEDDED_ROOT_MAP_BYTES,
};

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
    CoreNodeConfig, IPDiversityConfig, MultiAddr, NodeMode, P2PNode, PeerId,
};
pub use ant_protocol::{DevnetManifest, MAX_CHUNK_SIZE, MAX_WIRE_MESSAGE_SIZE};

// Re-export EVM types needed by CLI for wallet and network setup
pub use ant_protocol::evm::{
    Address as EvmAddress, CustomNetwork, Network as EvmNetwork, Wallet, U256,
};
