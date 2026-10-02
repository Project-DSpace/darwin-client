//! Chunk message types for the ANT protocol.
//!
//! Chunks are immutable, content-addressed data blocks where the address
//! is the BLAKE3 hash of the content. Maximum size is 4MB.
//!
//! This module defines the wire protocol messages for chunk operations
//! using postcard serialization for compact, fast encoding.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Protocol identifier for chunk operations.
pub const CHUNK_PROTOCOL_ID: &str = "autonomi.ant.chunk.v1";

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum chunk size in bytes (4MB).
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum wire message size in bytes (5MB).
///
/// Limits the input buffer accepted by [`ChunkMessage::decode`] to prevent
/// unbounded allocation from malicious or corrupted payloads. Set slightly
/// above [`MAX_CHUNK_SIZE`] to accommodate message envelope overhead.
pub const MAX_WIRE_MESSAGE_SIZE: usize = 5 * 1024 * 1024;

/// Data type identifier for chunks.
pub const DATA_TYPE_CHUNK: u32 = 0;

/// Settlement rules this build pays and verifies under.
///
/// Separate from [`PROTOCOL_VERSION`] on purpose. That one tracks the *wire*:
/// what a peer can parse. This one tracks the *money*: how a client turns a
/// signed quote into an on-chain payment. The two move independently, and
/// conflating them is what made this constant necessary.
///
/// Version 1 is the ADR-0008 rule set: a merkle batch settles at
/// `3 x median16(price) x 2^depth`, matching the single-node path.
///
/// **Bump this whenever a change makes an older client pay an amount storers
/// will refuse.** The multiplier moving, the median rule changing, the payable
/// field being redefined: all of those. A change that only alters *how much* a
/// node quotes does not qualify, because the client pays whatever it is
/// quoted; a change to the arithmetic *applied* to that quote does.
///
/// # Why this exists
///
/// ADR-0008 raised the merkle multiplier to 3x in client code and enforced it
/// in node code, but changed no wire type. Nothing gated the two together, so
/// clients built before the change kept collecting quotes, kept paying 1x, and
/// had their uploads refused by every storer *after* the on-chain payment had
/// already settled. The money was unrecoverable and the client had no idea why.
///
/// Carrying the version in the quote request lets a storer refuse to quote a
/// client it knows cannot pay correctly, before that client spends anything.
pub const CURRENT_SETTLEMENT_VERSION: u32 = 1;

/// Oldest settlement version this build will issue a quote for.
///
/// Kept as a separate constant from [`CURRENT_SETTLEMENT_VERSION`] so a
/// settlement change can ship without immediately locking out the previous
/// client generation: raise `CURRENT` first, let clients adopt, raise `MIN`
/// once the payment rule actually changes. They are equal today because
/// version 1 is the first versioned rule set, so there is no earlier one to
/// keep serving.
pub const MIN_SUPPORTED_SETTLEMENT_VERSION: u32 = 1;

/// Whether a storer on this build can promise to accept what a client
/// settling under `client_version` will pay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementCompatibility {
    /// Both sides settle the same way. Safe to quote.
    Compatible,
    /// The client settles under rules this build has superseded. Its payment
    /// would be refused, so it must not be quoted.
    ClientTooOld,
    /// The client settles under rules this build does not know. **This build
    /// is the old one**, and it cannot promise to accept the resulting
    /// payment, so it must not be quoted either.
    NodeTooOld,
}

/// Can a storer on this build safely quote a client settling under
/// `client_version`?
///
/// Unversioned clients never reach this: they send the legacy request variants
/// and are handled by policy in the storer, not here.
///
/// # Why both ends are bounded
///
/// An earlier revision accepted everything at or above
/// [`MIN_SUPPORTED_SETTLEMENT_VERSION`], on the reasoning that a storer
/// verifies whatever payment actually arrives so letting a newer client
/// through weakens nothing. That is only true when a settlement change raises
/// what is paid: ADR-0008's 3x cleared an old node's 1x minimum, so old nodes
/// accepted new clients for free. It is **not** true in general. A change that
/// redefines the median rule, or which field the contract pays from, produces
/// a payment an older verifier rejects, and by then the client has already
/// settled on-chain and cannot be refunded. That is the exact failure this
/// mechanism exists to prevent, so an unknown-newer version is refused rather
/// than assumed compatible.
///
/// The two refusals are kept apart because they need opposite handling.
/// [`SettlementCompatibility::ClientTooOld`] is terminal and the user must
/// upgrade. [`SettlementCompatibility::NodeTooOld`] says nothing about the
/// client, which should simply use a different storer. Collapsing them would
/// either tell up-to-date users to upgrade, or strand new clients whenever the
/// node fleet lags, which is the normal state during a client-first rollout.
#[must_use]
pub const fn settlement_compatibility(client_version: u32) -> SettlementCompatibility {
    if client_version < MIN_SUPPORTED_SETTLEMENT_VERSION {
        SettlementCompatibility::ClientTooOld
    } else if client_version > CURRENT_SETTLEMENT_VERSION {
        SettlementCompatibility::NodeTooOld
    } else {
        SettlementCompatibility::Compatible
    }
}

/// Number of nodes in a Kademlia close group.
///
/// Clients fetch quotes from the `CLOSE_GROUP_SIZE` closest nodes to a target
/// address and select the median-priced quote for payment.
pub const CLOSE_GROUP_SIZE: usize = 7;

/// Minimum number of close group members that must agree for a decision to be valid.
///
/// This is a simple majority: `(CLOSE_GROUP_SIZE / 2) + 1`.
pub const CLOSE_GROUP_MAJORITY: usize = (CLOSE_GROUP_SIZE / 2) + 1;

/// Content-addressed identifier (32 bytes).
pub type XorName = [u8; 32];

/// Byte length of an [`XorName`].
pub const XORNAME_LEN: usize = std::mem::size_of::<XorName>();

/// Enum of all chunk protocol message types.
///
/// Uses a single-byte discriminant for efficient wire encoding.
///
/// Marked `#[non_exhaustive]` so new message variants can be added
/// in a minor release without breaking downstream `match` expressions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChunkMessageBody {
    /// Request to store a chunk.
    PutRequest(ChunkPutRequest),
    /// Response to a PUT request.
    PutResponse(ChunkPutResponse),
    /// Request to retrieve a chunk.
    GetRequest(ChunkGetRequest),
    /// Response to a GET request.
    GetResponse(ChunkGetResponse),
    /// Request a storage quote.
    QuoteRequest(ChunkQuoteRequest),
    /// Response with a storage quote.
    QuoteResponse(ChunkQuoteResponse),
    /// Request a merkle candidate quote for batch payments.
    MerkleCandidateQuoteRequest(MerkleCandidateQuoteRequest),
    /// Response with a merkle candidate quote.
    MerkleCandidateQuoteResponse(MerkleCandidateQuoteResponse),
    /// Request a storage quote, declaring the client's settlement version.
    ///
    /// Appended after [`Self::MerkleCandidateQuoteResponse`] so every
    /// discriminant above keeps its wire value and existing peers decode
    /// unchanged. A peer built before this variant existed rejects it cleanly
    /// as an unknown discriminant rather than misreading it.
    QuoteRequestV2(ChunkQuoteRequestV2),
    /// Request a merkle candidate quote, declaring the client's settlement
    /// version. Appended for the same reason as [`Self::QuoteRequestV2`].
    MerkleCandidateQuoteRequestV2(MerkleCandidateQuoteRequestV2),
    /// Request to store or update a pointer.
    ///
    /// Appended after every existing variant for the reason given on
    /// [`Self::QuoteRequestV2`]: discriminants above keep their wire values, and
    /// a peer built before pointers existed rejects this cleanly as an unknown
    /// discriminant rather than misreading it.
    PointerPutRequest(PointerPutRequest),
    /// Response to a pointer PUT.
    PointerPutResponse(PointerPutResponse),
    /// Request to retrieve a pointer.
    PointerGetRequest(PointerGetRequest),
    /// Response to a pointer GET.
    PointerGetResponse(PointerGetResponse),
}

// =============================================================================
// Pointer PUT / GET
// =============================================================================

/// Request to store or update a pointer.
///
/// `record` is the whole [`Pointer`](crate::pointer::Pointer) encoding. There is
/// no separate address field: a pointer's address is a pure function of the
/// owner key inside the record, so a second copy could only ever disagree with
/// it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerPutRequest {
    /// The canonical pointer encoding.
    pub record: Bytes,
    /// Optional payment proof (serialized `ProofOfPayment`).
    ///
    /// Quoted and paid against the record's `state_id`, not its address: the
    /// address is stable for the pointer's life, so paying against it would
    /// make every update after the first free.
    pub payment_proof: Option<Vec<u8>>,
}

impl PointerPutRequest {
    /// Create a PUT request with no payment proof.
    #[must_use]
    pub const fn new(record: Bytes) -> Self {
        Self {
            record,
            payment_proof: None,
        }
    }

    /// Create a PUT request carrying a payment proof.
    #[must_use]
    pub const fn with_payment(record: Bytes, payment_proof: Vec<u8>) -> Self {
        Self {
            record,
            payment_proof: Some(payment_proof),
        }
    }
}

/// Response to a pointer PUT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PointerPutResponse {
    /// The pointer was stored, or replaced what was held.
    ///
    /// `state_id` names what the node now holds, so a client can tell an
    /// accepted update from one that lost a race.
    Success {
        /// The pointer's address.
        address: XorName,
        /// The state now held at that address.
        state_id: XorName,
    },
    /// The node already held this exact state. Nothing was written.
    ///
    /// Distinct from `Success` because it is what a re-submission of a paid
    /// state gets: the update is not lost, but it bought nothing either.
    Unchanged {
        /// The pointer's address.
        address: XorName,
        /// The state held, which equals the one submitted.
        state_id: XorName,
    },
    /// The submitted record lost to what the node already holds.
    Stale {
        /// The pointer's address.
        address: XorName,
        /// The state the node holds instead.
        state_id: XorName,
    },
    /// Payment is required to store this state.
    PaymentRequired {
        /// Error message.
        message: String,
    },
    /// An error occurred.
    Error(ProtocolError),
}

/// Request to retrieve a pointer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerGetRequest {
    /// The pointer address to retrieve.
    pub address: XorName,
}

impl PointerGetRequest {
    /// Create a GET request for `address`.
    #[must_use]
    pub const fn new(address: XorName) -> Self {
        Self { address }
    }
}

/// Response to a pointer GET.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PointerGetResponse {
    /// The pointer held at the requested address.
    Success {
        /// The canonical pointer encoding.
        record: Bytes,
    },
    /// No pointer is held at that address.
    NotFound {
        /// The address asked for.
        address: XorName,
    },
    /// An error occurred.
    Error(ProtocolError),
}

/// Wire-format wrapper that pairs a sender-assigned `request_id` with
/// a [`ChunkMessageBody`].
///
/// The sender picks a unique `request_id`; the handler echoes it back
/// in the response so callers can correlate replies by ID rather than
/// by source peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMessage {
    /// Sender-assigned identifier, echoed back in the response.
    pub request_id: u64,
    /// The protocol message body.
    pub body: ChunkMessageBody,
}

impl ChunkMessage {
    /// Encode the message to bytes using postcard.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        postcard::to_stdvec(self).map_err(|e| ProtocolError::SerializationFailed(e.to_string()))
    }

    /// Decode a message from bytes using postcard.
    ///
    /// Rejects payloads larger than [`MAX_WIRE_MESSAGE_SIZE`] before
    /// attempting deserialization.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::MessageTooLarge`] if the input exceeds the
    /// size limit, or [`ProtocolError::DeserializationFailed`] if postcard
    /// cannot parse the data.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge {
                size: data.len(),
                max_size: MAX_WIRE_MESSAGE_SIZE,
            });
        }
        postcard::from_bytes(data).map_err(|e| ProtocolError::DeserializationFailed(e.to_string()))
    }
}

// =============================================================================
// PUT Request/Response
// =============================================================================

/// Request to store a chunk.
///
/// `content` is held as `bytes::Bytes` so that callers fanning the same
/// chunk out to multiple recipients (e.g. close-group replication) share a
/// single backing buffer via refcount instead of deep-copying the 4 MB
/// payload per peer. Wire format is unchanged: `Bytes` serializes as a
/// byte sequence, identical to `Vec<u8>` under postcard/serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPutRequest {
    /// The content-addressed identifier (BLAKE3 of content).
    pub address: XorName,
    /// The chunk data.
    pub content: Bytes,
    /// Optional payment proof (serialized `ProofOfPayment`).
    /// Required for new chunks unless already verified.
    pub payment_proof: Option<Vec<u8>>,
}

impl ChunkPutRequest {
    /// Create a new PUT request.
    #[must_use]
    pub fn new(address: XorName, content: Bytes) -> Self {
        Self {
            address,
            content,
            payment_proof: None,
        }
    }

    /// Create a new PUT request with payment proof.
    #[must_use]
    pub fn with_payment(address: XorName, content: Bytes, payment_proof: Vec<u8>) -> Self {
        Self {
            address,
            content,
            payment_proof: Some(payment_proof),
        }
    }
}

/// Response to a PUT request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChunkPutResponse {
    /// Chunk stored successfully.
    Success {
        /// The address where the chunk was stored.
        address: XorName,
    },
    /// Chunk already exists (idempotent success).
    AlreadyExists {
        /// The existing chunk address.
        address: XorName,
    },
    /// Payment is required to store this chunk.
    PaymentRequired {
        /// Error message.
        message: String,
    },
    /// An error occurred.
    Error(ProtocolError),
}

// =============================================================================
// GET Request/Response
// =============================================================================

/// Request to retrieve a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkGetRequest {
    /// The content-addressed identifier to retrieve.
    pub address: XorName,
}

impl ChunkGetRequest {
    /// Create a new GET request.
    #[must_use]
    pub fn new(address: XorName) -> Self {
        Self { address }
    }
}

/// Response to a GET request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChunkGetResponse {
    /// Chunk found and returned.
    Success {
        /// The chunk address.
        address: XorName,
        /// The chunk data.
        content: Vec<u8>,
    },
    /// Chunk not found.
    NotFound {
        /// The requested address.
        address: XorName,
    },
    /// An error occurred.
    Error(ProtocolError),
}

// =============================================================================
// Quote Request/Response
// =============================================================================

/// Request a storage quote for a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkQuoteRequest {
    /// The content address of the data to store.
    pub address: XorName,
    /// Size of the data in bytes.
    pub data_size: u64,
    /// Data type identifier (0 for chunks).
    pub data_type: u32,
}

impl ChunkQuoteRequest {
    /// Create a new quote request.
    #[must_use]
    pub fn new(address: XorName, data_size: u64) -> Self {
        Self {
            address,
            data_size,
            data_type: DATA_TYPE_CHUNK,
        }
    }
}

/// Request a storage quote, declaring the settlement rules the client pays
/// under.
///
/// Same fields as [`ChunkQuoteRequest`] plus `settlement_version`. A separate
/// struct rather than a field on the original, because [`ChunkMessage`] is
/// postcard-encoded and postcard is not self-describing: adding a field would
/// silently change how every existing peer reads the message, while adding a
/// variant is rejected cleanly by peers that do not know it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkQuoteRequestV2 {
    /// The content address of the data to store.
    pub address: XorName,
    /// Size of the data in bytes.
    pub data_size: u64,
    /// Data type identifier (0 for chunks).
    pub data_type: u32,
    /// The settlement rules this client pays under. See
    /// [`CURRENT_SETTLEMENT_VERSION`].
    pub settlement_version: u32,
}

impl ChunkQuoteRequestV2 {
    /// Create a new quote request declaring this build's settlement version.
    #[must_use]
    pub fn new(address: XorName, data_size: u64) -> Self {
        Self {
            address,
            data_size,
            data_type: DATA_TYPE_CHUNK,
            settlement_version: CURRENT_SETTLEMENT_VERSION,
        }
    }
}

/// Response with a storage quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChunkQuoteResponse {
    /// Quote generated successfully.
    ///
    /// When `already_stored` is `true` the node already holds this chunk and no
    /// payment is required — the client should skip the pay-then-PUT cycle for
    /// this address. The quote is still included for informational purposes.
    Success {
        /// Serialized `PaymentQuote`.
        quote: Vec<u8>,
        /// `true` when the chunk already exists on this node (skip payment).
        already_stored: bool,
        /// ADR-0004: the serialized signed storage commitment the quote's price
        /// was derived from, so the client can verify the binding before paying
        /// ("the commitment arrived with the quote") and forward it as a sidecar
        /// in the PUT bundle. `None` for a baseline quote (no commitment to
        /// pin), or from a node that has not yet rotated a commitment. Opaque
        /// bytes: `ant-protocol` stays agnostic of `ant-node`'s commitment type;
        /// the client resolves it only to match the quote's `commitment_pin`.
        ///
        /// NOTE: this enum is encoded with **postcard** (see [`ChunkMessage::encode`]),
        /// which is non-self-describing — `#[serde(default)]` does NOT make an
        /// old-format `Success` (without this field) decode against new code, and
        /// vice versa. ADR-0004 is a HARD CUTOVER: the whole fleet and clients
        /// upgrade together, so old/new `ChunkQuoteResponse` never interoperate.
        /// The attribute only keeps `Default`-based construction ergonomic; it is
        /// not a wire-compat guarantee. (Contrast `PaymentQuote`/`PaymentProof`,
        /// which ARE rmp-encoded, where tail `serde(default)` is decode-compatible.)
        #[serde(default)]
        commitment: Option<Vec<u8>>,
    },
    /// Quote generation failed.
    Error(ProtocolError),
}

// =============================================================================
// Merkle Candidate Quote Request/Response
// =============================================================================

/// Request a merkle candidate quote for batch payments.
///
/// Part of the merkle batch payment system where clients collect
/// signed candidate quotes from 16 closest peers per pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleCandidateQuoteRequest {
    /// The candidate pool address (hash of midpoint || root || timestamp).
    pub address: XorName,
    /// Data type identifier (0 for chunks).
    pub data_type: u32,
    /// Size of the data in bytes.
    pub data_size: u64,
    /// Client-provided merkle payment timestamp (unix seconds).
    pub merkle_payment_timestamp: u64,
}

/// Request a merkle candidate quote, declaring the settlement rules the client
/// pays under.
///
/// Same fields as [`MerkleCandidateQuoteRequest`] plus `settlement_version`.
/// See [`ChunkQuoteRequestV2`] for why this is a separate struct.
///
/// This is the variant that matters most for the merkle path: a batch pays
/// on-chain **before** any storer sees a PUT, so a storer that only checks the
/// settlement rule at PUT time is checking it after the money is gone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleCandidateQuoteRequestV2 {
    /// The candidate pool address (hash of midpoint || root || timestamp).
    pub address: XorName,
    /// Data type identifier (0 for chunks).
    pub data_type: u32,
    /// Size of the data in bytes.
    pub data_size: u64,
    /// Client-provided merkle payment timestamp (unix seconds).
    pub merkle_payment_timestamp: u64,
    /// The settlement rules this client pays under. See
    /// [`CURRENT_SETTLEMENT_VERSION`].
    pub settlement_version: u32,
}

impl MerkleCandidateQuoteRequestV2 {
    /// Create a new merkle candidate quote request declaring this build's
    /// settlement version.
    #[must_use]
    pub fn new(address: XorName, data_size: u64, merkle_payment_timestamp: u64) -> Self {
        Self {
            address,
            data_type: DATA_TYPE_CHUNK,
            data_size,
            merkle_payment_timestamp,
            settlement_version: CURRENT_SETTLEMENT_VERSION,
        }
    }
}

/// Response with a merkle candidate quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MerkleCandidateQuoteResponse {
    /// Candidate quote generated successfully.
    /// Contains the serialized `MerklePaymentCandidateNode`.
    Success {
        /// Serialized `MerklePaymentCandidateNode`.
        candidate_node: Vec<u8>,
        /// ADR-0004: the serialized signed storage commitment the candidate's
        /// price was derived from, so the client can fully resolve the binding
        /// BEFORE paying (resolve-before-pay). `None` for a baseline candidate.
        /// Unlike the single-node path, this commitment is NOT forwarded in the
        /// merkle PUT bundle — sixteen per-candidate sidecars exceeded the
        /// storer's payment-proof size budget, so current clients omit them and
        /// storers resolve merkle pins from gossip or a `GetCommitmentByPin`
        /// fetch (`MerklePaymentProof.commitment_sidecars` stays for legacy
        /// bundles). Same semantics as
        /// [`ChunkQuoteResponse::Success::commitment`]; postcard-encoded, so
        /// this is a hard-cutover field, not an interop guarantee.
        #[serde(default)]
        commitment: Option<Vec<u8>>,
    },
    /// Quote generation failed.
    Error(ProtocolError),
}

// =============================================================================
// Payment Proof Type Tags
// =============================================================================

/// Version byte prefix for payment proof serialization.
/// Allows the verifier to detect proof type before deserialization.
pub const PROOF_TAG_SINGLE_NODE: u8 = 0x01;
/// Version byte prefix for merkle payment proofs.
pub const PROOF_TAG_MERKLE: u8 = 0x02;

// =============================================================================
// Protocol Errors
// =============================================================================

/// Errors that can occur during protocol operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Message serialization failed.
    SerializationFailed(String),
    /// Message deserialization failed.
    DeserializationFailed(String),
    /// Wire message exceeds the maximum allowed size.
    MessageTooLarge {
        /// Actual size of the message in bytes.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },
    /// Chunk exceeds maximum size.
    ChunkTooLarge {
        /// Size of the chunk in bytes.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },
    /// Content address mismatch (hash(content) != address).
    AddressMismatch {
        /// Expected address.
        expected: XorName,
        /// Actual address computed from content.
        actual: XorName,
    },
    /// Storage operation failed.
    StorageFailed(String),
    /// Payment verification failed.
    PaymentFailed(String),
    /// Quote generation failed.
    QuoteFailed(String),
    /// Internal error.
    Internal(String),
    /// The client settles payments under rules this node no longer accepts, so
    /// no quote was issued.
    ///
    /// Refused at quote time on purpose. A client that pays under superseded
    /// rules produces an on-chain payment every storer will reject, and that
    /// payment cannot be refunded, so the only useful place to stop it is
    /// before the client spends anything.
    ///
    /// Appended last so existing variants keep their wire discriminants. A
    /// peer old enough not to know this variant cannot be sent it: it would
    /// have had to send a V2 request to earn it, and only builds that carry
    /// this variant do that.
    ClientUpdateRequired {
        /// Settlement version the client declared.
        client_settlement_version: u32,
        /// Oldest settlement version this node will quote for.
        min_settlement_version: u32,
    },
    /// This node settles under older rules than the client, so it declined to
    /// quote rather than promise to accept a payment it may not recognise.
    ///
    /// The mirror image of [`Self::ClientUpdateRequired`], and deliberately a
    /// separate variant: it is not a verdict about the client, and a client
    /// that receives it should quietly use a different storer rather than tell
    /// its user anything. During a client-first rollout most of the fleet is
    /// briefly in this state, so treating it as a client fault would strand
    /// every up-to-date user.
    StorerUpdateRequired {
        /// Settlement version the client declared.
        client_settlement_version: u32,
        /// Newest settlement version this node understands.
        node_settlement_version: u32,
    },
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "deserialization failed: {msg}"),
            Self::MessageTooLarge { size, max_size } => {
                write!(f, "message size {size} exceeds maximum {max_size}")
            }
            Self::ChunkTooLarge { size, max_size } => {
                write!(f, "chunk size {size} exceeds maximum {max_size}")
            }
            Self::AddressMismatch { expected, actual } => {
                write!(
                    f,
                    "address mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Self::StorageFailed(msg) => write!(f, "storage failed: {msg}"),
            Self::PaymentFailed(msg) => write!(f, "payment failed: {msg}"),
            Self::QuoteFailed(msg) => write!(f, "quote failed: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
            Self::ClientUpdateRequired {
                client_settlement_version,
                min_settlement_version,
            } => write!(
                f,
                "{}",
                client_update_required_message(*client_settlement_version, *min_settlement_version)
            ),
            Self::StorerUpdateRequired {
                client_settlement_version,
                node_settlement_version,
            } => write!(
                f,
                "this node settles under version {node_settlement_version} and cannot \
                 promise to accept a version {client_settlement_version} payment, so it \
                 issued no quote. Nothing was charged; use a different storer."
            ),
        }
    }
}

/// The upgrade instruction shown to a user whose client cannot settle
/// correctly.
///
/// A free function rather than only a `Display` arm so the storer can log the
/// same wording it sends back, and so the client can reuse it when it
/// translates the rejection into a CLI error. Kept deliberately plain: the
/// reader is an end user staring at a failed upload, not an operator.
#[must_use]
pub fn client_update_required_message(
    client_settlement_version: u32,
    min_settlement_version: u32,
) -> String {
    format!(
        "your client is too old to pay the current storage rate \
         (it settles under version {client_settlement_version}, this node requires \
         at least {min_settlement_version}), so no quote was issued and nothing was \
         charged. Run `ant update` to upgrade, or reinstall from \
         https://github.com/WithAutonomi/ant-client/releases/latest"
    )
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_put_request_encode_decode() {
        let address = [0xAB; 32];
        let content = Bytes::from_static(&[1, 2, 3, 4, 5]);
        let request = ChunkPutRequest::new(address, content.clone());
        let msg = ChunkMessage {
            request_id: 42,
            body: ChunkMessageBody::PutRequest(request),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 42);
        if let ChunkMessageBody::PutRequest(req) = decoded.body {
            assert_eq!(req.address, address);
            assert_eq!(req.content, content);
            assert!(req.payment_proof.is_none());
        } else {
            panic!("expected PutRequest");
        }
    }

    #[test]
    fn test_put_request_with_payment() {
        let address = [0xAB; 32];
        let content = Bytes::from_static(&[1, 2, 3, 4, 5]);
        let payment = vec![10, 20, 30];
        let request = ChunkPutRequest::with_payment(address, content.clone(), payment.clone());

        assert_eq!(request.address, address);
        assert_eq!(request.content, content);
        assert_eq!(request.payment_proof, Some(payment));
    }

    #[test]
    fn test_get_request_encode_decode() {
        let address = [0xCD; 32];
        let request = ChunkGetRequest::new(address);
        let msg = ChunkMessage {
            request_id: 7,
            body: ChunkMessageBody::GetRequest(request),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 7);
        if let ChunkMessageBody::GetRequest(req) = decoded.body {
            assert_eq!(req.address, address);
        } else {
            panic!("expected GetRequest");
        }
    }

    #[test]
    fn test_put_response_success() {
        let address = [0xEF; 32];
        let response = ChunkPutResponse::Success { address };
        let msg = ChunkMessage {
            request_id: 99,
            body: ChunkMessageBody::PutResponse(response),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 99);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) =
            decoded.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected PutResponse::Success");
        }
    }

    #[test]
    fn test_get_response_not_found() {
        let address = [0x12; 32];
        let response = ChunkGetResponse::NotFound { address };
        let msg = ChunkMessage {
            request_id: 0,
            body: ChunkMessageBody::GetResponse(response),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 0);
        if let ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address: addr }) =
            decoded.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected GetResponse::NotFound");
        }
    }

    #[test]
    fn test_quote_request_encode_decode() {
        let address = [0x34; 32];
        let request = ChunkQuoteRequest::new(address, 1024);
        let msg = ChunkMessage {
            request_id: 1,
            body: ChunkMessageBody::QuoteRequest(request),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 1);
        if let ChunkMessageBody::QuoteRequest(req) = decoded.body {
            assert_eq!(req.address, address);
            assert_eq!(req.data_size, 1024);
            assert_eq!(req.data_type, DATA_TYPE_CHUNK);
        } else {
            panic!("expected QuoteRequest");
        }
    }

    #[test]
    fn test_protocol_error_display() {
        let err = ProtocolError::ChunkTooLarge {
            size: 5_000_000,
            max_size: MAX_CHUNK_SIZE,
        };
        assert!(err.to_string().contains("5000000"));
        assert!(err.to_string().contains(&MAX_CHUNK_SIZE.to_string()));

        let err = ProtocolError::AddressMismatch {
            expected: [0xAA; 32],
            actual: [0xBB; 32],
        };
        let display = err.to_string();
        assert!(display.contains("address mismatch"));
    }

    #[test]
    fn test_decode_rejects_oversized_payload() {
        let oversized = vec![0u8; MAX_WIRE_MESSAGE_SIZE + 1];
        let result = ChunkMessage::decode(&oversized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProtocolError::MessageTooLarge { .. }),
            "expected MessageTooLarge, got {err:?}"
        );
    }

    #[test]
    fn test_invalid_decode() {
        let invalid_data = vec![0xFF, 0xFF, 0xFF];
        let result = ChunkMessage::decode(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(CHUNK_PROTOCOL_ID, "autonomi.ant.chunk.v1");
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAX_CHUNK_SIZE, 4 * 1024 * 1024);
        assert_eq!(DATA_TYPE_CHUNK, 0);
    }

    #[test]
    fn test_proof_tag_constants() {
        // Tags must be distinct non-zero bytes
        assert_ne!(PROOF_TAG_SINGLE_NODE, PROOF_TAG_MERKLE);
        assert_ne!(PROOF_TAG_SINGLE_NODE, 0x00);
        assert_ne!(PROOF_TAG_MERKLE, 0x00);
        assert_eq!(PROOF_TAG_SINGLE_NODE, 0x01);
        assert_eq!(PROOF_TAG_MERKLE, 0x02);
    }

    #[test]
    fn test_merkle_candidate_quote_request_encode_decode() {
        let address = [0x56; 32];
        let request = MerkleCandidateQuoteRequest {
            address,
            data_type: DATA_TYPE_CHUNK,
            data_size: 2048,
            merkle_payment_timestamp: 1_700_000_000,
        };
        let msg = ChunkMessage {
            request_id: 500,
            body: ChunkMessageBody::MerkleCandidateQuoteRequest(request),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 500);
        if let ChunkMessageBody::MerkleCandidateQuoteRequest(req) = decoded.body {
            assert_eq!(req.address, address);
            assert_eq!(req.data_type, DATA_TYPE_CHUNK);
            assert_eq!(req.data_size, 2048);
            assert_eq!(req.merkle_payment_timestamp, 1_700_000_000);
        } else {
            panic!("expected MerkleCandidateQuoteRequest");
        }
    }

    #[test]
    fn test_merkle_candidate_quote_response_success_encode_decode() {
        let candidate_node_bytes = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let response = MerkleCandidateQuoteResponse::Success {
            candidate_node: candidate_node_bytes.clone(),
            commitment: Some(vec![0x11, 0x22]),
        };
        let msg = ChunkMessage {
            request_id: 501,
            body: ChunkMessageBody::MerkleCandidateQuoteResponse(response),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 501);
        if let ChunkMessageBody::MerkleCandidateQuoteResponse(
            MerkleCandidateQuoteResponse::Success {
                candidate_node,
                commitment,
            },
        ) = decoded.body
        {
            assert_eq!(candidate_node, candidate_node_bytes);
            assert_eq!(commitment, Some(vec![0x11, 0x22]));
        } else {
            panic!("expected MerkleCandidateQuoteResponse::Success");
        }
    }

    #[test]
    fn test_merkle_candidate_quote_response_error_encode_decode() {
        let error = ProtocolError::QuoteFailed("no libp2p keypair".to_string());
        let response = MerkleCandidateQuoteResponse::Error(error.clone());
        let msg = ChunkMessage {
            request_id: 502,
            body: ChunkMessageBody::MerkleCandidateQuoteResponse(response),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 502);
        if let ChunkMessageBody::MerkleCandidateQuoteResponse(
            MerkleCandidateQuoteResponse::Error(err),
        ) = decoded.body
        {
            assert_eq!(err, error);
        } else {
            panic!("expected MerkleCandidateQuoteResponse::Error");
        }
    }

    // =========================================================================
    // Settlement version
    // =========================================================================

    /// Discriminant of a message body, read straight off the wire.
    ///
    /// `request_id: 0` encodes as a single varint byte, so the body's variant
    /// index is byte 1. Reading it directly is the point: it is what a peer
    /// built against an older `ant-protocol` sees.
    fn wire_discriminant(body: ChunkMessageBody) -> u8 {
        let encoded = ChunkMessage {
            request_id: 0,
            body,
        }
        .encode()
        .expect("encode should succeed");
        *encoded.get(1).expect("body discriminant should be present")
    }

    /// The load-bearing test for this whole design.
    ///
    /// The settlement version ships as appended variants precisely so existing
    /// peers keep decoding. That only holds while every prior variant keeps
    /// its wire index, which postcard assigns by declaration order. Insert a
    /// variant anywhere but the end and every older peer silently misreads
    /// every message from this one. Pinning the indices turns that from a
    /// production incident into a failing test.
    #[test]
    fn appending_v2_variants_leaves_existing_discriminants_untouched() {
        let address = [0x11; 32];

        assert_eq!(
            wire_discriminant(ChunkMessageBody::PutRequest(ChunkPutRequest::new(
                address,
                Bytes::from_static(&[1]),
            ))),
            0,
        );
        assert_eq!(
            wire_discriminant(ChunkMessageBody::GetRequest(ChunkGetRequest { address })),
            2,
        );
        assert_eq!(
            wire_discriminant(ChunkMessageBody::QuoteRequest(ChunkQuoteRequest::new(
                address, 1024,
            ))),
            4,
        );
        assert_eq!(
            wire_discriminant(ChunkMessageBody::MerkleCandidateQuoteRequest(
                MerkleCandidateQuoteRequest {
                    address,
                    data_type: DATA_TYPE_CHUNK,
                    data_size: 1024,
                    merkle_payment_timestamp: 1_785_855_600,
                }
            )),
            6,
        );

        // Responses carry the same obligation as requests: a peer decoding a
        // reply reads the same discriminant space, so pinning only the request
        // half would let a response variant be reordered without any test
        // noticing.
        assert_eq!(
            wire_discriminant(ChunkMessageBody::PutResponse(ChunkPutResponse::Success {
                address
            })),
            1,
        );
        assert_eq!(
            wire_discriminant(ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound {
                address
            })),
            3,
        );
        assert_eq!(
            wire_discriminant(ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(
                ProtocolError::Internal(String::new())
            ))),
            5,
        );
        assert_eq!(
            wire_discriminant(ChunkMessageBody::MerkleCandidateQuoteResponse(
                MerkleCandidateQuoteResponse::Error(ProtocolError::Internal(String::new()))
            )),
            7,
        );

        // The new variants take the next free indices, above everything an
        // older peer knows, so it rejects them as unknown rather than
        // misreading a variant it does know.
        assert_eq!(
            wire_discriminant(ChunkMessageBody::QuoteRequestV2(ChunkQuoteRequestV2::new(
                address, 1024,
            ))),
            8,
        );
        assert_eq!(
            wire_discriminant(ChunkMessageBody::MerkleCandidateQuoteRequestV2(
                MerkleCandidateQuoteRequestV2::new(address, 1024, 1_785_855_600)
            )),
            9,
        );
    }

    /// `ProtocolError` rides inside quote responses, so its variants carry the
    /// same append-only obligation as the message bodies.
    #[test]
    fn client_update_required_is_appended_to_protocol_error() {
        let encode = |e: &ProtocolError| postcard::to_stdvec(e).expect("encode should succeed");

        assert_eq!(
            encode(&ProtocolError::SerializationFailed(String::new()))
                .first()
                .copied(),
            Some(0),
        );
        assert_eq!(
            encode(&ProtocolError::DeserializationFailed(String::new()))
                .first()
                .copied(),
            Some(1),
        );
        assert_eq!(
            encode(&ProtocolError::MessageTooLarge {
                size: 0,
                max_size: 0
            })
            .first()
            .copied(),
            Some(2),
        );
        assert_eq!(
            encode(&ProtocolError::ChunkTooLarge {
                size: 0,
                max_size: 0
            })
            .first()
            .copied(),
            Some(3),
        );
        assert_eq!(
            encode(&ProtocolError::AddressMismatch {
                expected: [0u8; 32],
                actual: [0u8; 32]
            })
            .first()
            .copied(),
            Some(4),
        );
        assert_eq!(
            encode(&ProtocolError::StorageFailed(String::new()))
                .first()
                .copied(),
            Some(5),
        );
        assert_eq!(
            encode(&ProtocolError::PaymentFailed(String::new()))
                .first()
                .copied(),
            Some(6),
        );
        assert_eq!(
            encode(&ProtocolError::QuoteFailed(String::new()))
                .first()
                .copied(),
            Some(7),
        );
        assert_eq!(
            encode(&ProtocolError::Internal(String::new()))
                .first()
                .copied(),
            Some(8),
        );
        assert_eq!(
            encode(&ProtocolError::ClientUpdateRequired {
                client_settlement_version: 0,
                min_settlement_version: 1,
            })
            .first()
            .copied(),
            Some(9),
        );
        assert_eq!(
            encode(&ProtocolError::StorerUpdateRequired {
                client_settlement_version: 2,
                node_settlement_version: 1,
            })
            .first()
            .copied(),
            Some(10),
        );
    }

    #[test]
    fn v2_quote_request_round_trips_with_the_settlement_version() {
        let address = [0x22; 32];
        let msg = ChunkMessage {
            request_id: 600,
            body: ChunkMessageBody::QuoteRequestV2(ChunkQuoteRequestV2::new(address, 4096)),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 600);
        if let ChunkMessageBody::QuoteRequestV2(req) = decoded.body {
            assert_eq!(req.address, address);
            assert_eq!(req.data_size, 4096);
            assert_eq!(req.data_type, DATA_TYPE_CHUNK);
            assert_eq!(req.settlement_version, CURRENT_SETTLEMENT_VERSION);
        } else {
            panic!("expected QuoteRequestV2");
        }
    }

    #[test]
    fn v2_merkle_candidate_request_round_trips_with_the_settlement_version() {
        let address = [0x33; 32];
        let msg = ChunkMessage {
            request_id: 601,
            body: ChunkMessageBody::MerkleCandidateQuoteRequestV2(
                MerkleCandidateQuoteRequestV2::new(address, 4096, 1_785_855_600),
            ),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 601);
        if let ChunkMessageBody::MerkleCandidateQuoteRequestV2(req) = decoded.body {
            assert_eq!(req.address, address);
            assert_eq!(req.data_size, 4096);
            assert_eq!(req.merkle_payment_timestamp, 1_785_855_600);
            assert_eq!(req.settlement_version, CURRENT_SETTLEMENT_VERSION);
        } else {
            panic!("expected MerkleCandidateQuoteRequestV2");
        }
    }

    #[test]
    fn settlement_compatibility_is_bounded_at_both_ends() {
        assert_eq!(
            settlement_compatibility(CURRENT_SETTLEMENT_VERSION),
            SettlementCompatibility::Compatible,
        );
        // The lower bound is inclusive: the oldest version still served is
        // served, not refused.
        assert_eq!(
            settlement_compatibility(MIN_SUPPORTED_SETTLEMENT_VERSION),
            SettlementCompatibility::Compatible,
        );
        assert_eq!(
            settlement_compatibility(MIN_SUPPORTED_SETTLEMENT_VERSION.saturating_sub(1)),
            SettlementCompatibility::ClientTooOld,
        );
    }

    /// The correction this replaced an earlier revision for. Serving a client
    /// whose settlement rules this build does not know means promising to
    /// accept a payment it may reject, and by the time it rejects, the client
    /// has settled on-chain and cannot be refunded. Only monotonic increases
    /// are safe to wave through, and nothing here can tell whether the next
    /// change is one.
    #[test]
    fn a_newer_settlement_version_is_refused_rather_than_assumed_compatible() {
        assert_eq!(
            settlement_compatibility(CURRENT_SETTLEMENT_VERSION.saturating_add(1)),
            SettlementCompatibility::NodeTooOld,
        );
    }

    /// The two refusals must stay distinct on the wire. One tells a user to
    /// upgrade; the other tells a client to pick a different peer and say
    /// nothing. Rendering them alike would strand every up-to-date user during
    /// a client-first rollout, when most of the fleet is briefly the old side.
    #[test]
    fn the_two_refusals_do_not_blame_the_same_party() {
        let client_at_fault = ProtocolError::ClientUpdateRequired {
            client_settlement_version: 0,
            min_settlement_version: 1,
        }
        .to_string();
        let node_at_fault = ProtocolError::StorerUpdateRequired {
            client_settlement_version: 2,
            node_settlement_version: 1,
        }
        .to_string();

        assert!(
            client_at_fault.contains("your client is too old"),
            "{client_at_fault}"
        );
        assert!(
            !node_at_fault.contains("your client is too old"),
            "{node_at_fault}"
        );
        assert!(
            node_at_fault.contains("use a different storer"),
            "{node_at_fault}"
        );
        // Neither costs the user anything, and both must say so.
        assert!(
            client_at_fault.contains("nothing was charged"),
            "{client_at_fault}"
        );
        assert!(
            node_at_fault.contains("Nothing was charged"),
            "{node_at_fault}"
        );
    }

    /// The rejection exists to get a user unstuck, so the wording is part of
    /// the contract, not decoration.
    #[test]
    fn update_required_message_tells_the_user_how_to_fix_it() {
        let rendered = ProtocolError::ClientUpdateRequired {
            client_settlement_version: 0,
            min_settlement_version: 1,
        }
        .to_string();

        assert!(rendered.contains("ant update"), "{rendered}");
        assert!(rendered.contains("too old"), "{rendered}");
        // The whole point is that refusing to quote costs the user nothing.
        assert!(rendered.contains("nothing was charged"), "{rendered}");
    }
}
