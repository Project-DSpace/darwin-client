//! Pointers — paid mutable references with an immutable owner.
//!
//! A pointer is a mutable, owner-signed reference stored at an address derived
//! from its owner's public key. Unlike a
//! [`DataChunk`](crate::data_types::DataChunk) its address is **not** its
//! content hash: the address is fixed for the pointer's life while the bytes
//! under it change with every update.
//!
//! Ownership is fixed at creation. There is no transfer, no lineage, no
//! certificates and no key rotation: a former owner keeps its key forever, so
//! transferable ownership cannot be made fork-proof by a local rule. An earlier
//! draft of this module implemented transfer through a genesis object and a
//! chain of transfer certificates; it was reviewed and withdrawn. See
//! `ADR-0016` in `ant-node`.
//!
//! That choice is what lets the design be this small: the owner key is inlined
//! in the record, so validating a pointer needs nothing but the pointer — no
//! fetch, no cache, no second close group, nothing that can be missing.
//!
//! # Encoding
//!
//! Encoded by hand: canonical, fixed-width, big-endian, no length prefixes and
//! no `serde`. The signed payload must not depend on a serializer whose output
//! can change — 1.0's pointer called `rmp_serde` inside its signing routine and
//! silently signed nothing when it failed.
//!
//! ```text
//! format_version  1     byte
//! owner        1952     bytes   ML-DSA-65 public key
//! counter         8     bytes   big-endian u64
//! target         33     bytes   1-byte kind tag + 32-byte address, opaque here
//! signature    3309     bytes   ML-DSA-65 over the preceding 1994 bytes
//!             -----
//!              5303     bytes
//! ```
//!
//! # Identity
//!
//! ```text
//! A        = BLAKE3::derive_key("autonomi.pointer.address.v1", owner)
//! state_id = BLAKE3::derive_key("autonomi.pointer.state.v1",   body)
//! ```
//!
//! Derive-key, not a hash of a prefix and the input. A chunk is addressed by a
//! plain hash of its content, so a prefix would put both of these inside the
//! chunk address space for anyone who could write the preimage down: squatting
//! an owner's address before they used it, or buying a pointer and a chunk with
//! one payment. Both modes still produce 32 bytes, so the ranges overlap; what
//! changed is that crossing them is the preimage problem BLAKE3 is assumed to
//! resist.
//!
//! `A` routes and decides which nodes are responsible. `state_id` names the
//! authenticated state: it is what sync hints carry, what a fetch decision
//! compares, and **what a quote is paid against**. They are separate because
//! `A` must be stable for the pointer's life while the paid identifier must
//! change with every update, or updates after the first would be free — the
//! defect this design exists to fix.
//!
//! # What this module does not do
//!
//! Payment verification, storage and replication. Those are the node's job.

use saorsa_pqc::api::sig::{
    ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
};

use crate::chunk::XORNAME_LEN;
use crate::data_types::XorName;

// =============================================================================
// Constants
// =============================================================================

/// Data type identifier for pointers, alongside
/// [`DATA_TYPE_CHUNK`](crate::chunk::DATA_TYPE_CHUNK).
pub const DATA_TYPE_POINTER: u32 = 1;

/// Wire format discriminator carried by every pointer.
///
/// Covered by the signature, so it cannot be downgraded, and part of the signed
/// body, so it reaches `state_id`: a record differing only in this byte is a
/// different state and is paid for separately.
pub const POINTER_FORMAT_VERSION: u8 = 1;

/// Length of a raw ML-DSA-65 public key.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// Length of a raw ML-DSA-65 signature.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// Length of an encoded [`PointerTarget`]: a kind tag plus an address.
pub const TARGET_WIRE_LEN: usize = 1 + XORNAME_LEN;

/// Byte offset of the owner key within an encoded pointer.
const OWNER_OFFSET: usize = 1;

/// Byte offset of the counter within an encoded pointer.
const COUNTER_OFFSET: usize = OWNER_OFFSET + ML_DSA_65_PUBLIC_KEY_LEN;

/// Byte offset of the target within an encoded pointer.
const TARGET_OFFSET: usize = COUNTER_OFFSET + 8;

/// Length of the signed body: everything before the signature.
pub const POINTER_BODY_LEN: usize = TARGET_OFFSET + TARGET_WIRE_LEN;

/// Total size of an encoded pointer.
pub const POINTER_WIRE_LEN: usize = POINTER_BODY_LEN + ML_DSA_65_SIGNATURE_LEN;

/// Key-derivation context for the pointer address.
///
/// Used with BLAKE3's `derive_key`, not as a hash prefix. A prefix separates
/// nothing: a chunk's address is `BLAKE3(content)`, so a chunk whose content is
/// the prefix followed by an owner key would land on exactly that owner's
/// pointer address, and an attacker could squat any address it could name.
/// `derive_key` runs BLAKE3 in a different mode. The two still share a 32-byte
/// range; what changes is that hitting a value from one mode with the other is
/// the preimage problem BLAKE3 is assumed to resist, rather than a string
/// anyone can write down.
const CONTEXT_ADDRESS: &str = "autonomi.pointer.address.v1";

/// Key-derivation context for the authenticated-state identifier.
///
/// Also `derive_key`, and for a sharper reason: `state_id` is what a pointer's
/// payment is quoted against. Were it a plain hash, one settled quote would pay
/// for both the pointer and a chunk sitting at the same address.
const CONTEXT_STATE: &str = "autonomi.pointer.state.v1";

/// ML-DSA signing context for a pointer.
///
/// Domain-separates a pointer signature from every other signature in the
/// system, so a signature lifted from elsewhere cannot authenticate a pointer
/// and vice versa.
const SIGNING_CONTEXT: &[u8] = b"autonomi.pointer.head.v1";

// =============================================================================
// Errors
// =============================================================================

/// Why a pointer was refused.
///
/// `Display` is written by hand rather than derived, because this crate is a
/// wire contract and does not take a macro dependency for it — the same reason
/// [`crate::error::Error`] is hand-written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerError {
    /// The encoding is not exactly [`POINTER_WIRE_LEN`] bytes.
    WrongLength(usize),
    /// The format version is not one this build understands.
    UnknownFormatVersion(u8),
    /// The owner key does not decode.
    InvalidOwnerKey(String),
    /// The signature does not decode.
    InvalidSignatureFormat(String),
    /// The signature does not verify under the owner key in the record.
    SignatureInvalid,
    /// Signing failed.
    SigningFailed(String),
    /// The counter is at its maximum and cannot be advanced.
    CounterExhausted,
}

impl std::fmt::Display for PointerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(f, "pointer must be {POINTER_WIRE_LEN} bytes, got {len}")
            }
            Self::UnknownFormatVersion(version) => {
                write!(f, "unknown pointer format version {version}")
            }
            Self::InvalidOwnerKey(reason) => write!(f, "invalid pointer owner key: {reason}"),
            Self::InvalidSignatureFormat(reason) => {
                write!(f, "invalid pointer signature format: {reason}")
            }
            Self::SignatureInvalid => {
                write!(f, "pointer signature does not verify under its owner key")
            }
            Self::SigningFailed(reason) => write!(f, "pointer signing failed: {reason}"),
            Self::CounterExhausted => write!(
                f,
                "pointer counter is at u64::MAX and is terminal; migrate to a fresh \
                 pointer with an earlier update"
            ),
        }
    }
}

impl std::error::Error for PointerError {}

// =============================================================================
// Address derivation
// =============================================================================

/// Derive a pointer address from an owner key.
///
/// `BLAKE3::derive_key` rather than a hash of a prefix and the key. Chunk
/// addresses are `BLAKE3(content)` over the same 32-byte range, and derive-key
/// is a different mode of the same function: the ranges still overlap, but
/// putting content on one of these values is a preimage problem rather than a
/// string anyone can write down. The node still refuses an address the other
/// kind occupies; that guard now covers the cryptographic case only.
#[must_use]
pub fn pointer_address(owner: &MlDsaPublicKey) -> XorName {
    blake3::derive_key(CONTEXT_ADDRESS, &owner.to_bytes())
}

/// Derive the authenticated-state identifier from a signed body.
///
/// Derive-key for the same reason as the address, and one more: this is the
/// identifier a pointer's storage is paid against, so a chunk that could occupy
/// it would be a second record bought with one payment.
#[must_use]
pub fn state_id_for_body(body: &[u8]) -> XorName {
    blake3::derive_key(CONTEXT_STATE, body)
}

// =============================================================================
// Target
// =============================================================================

/// What a pointer points at, as clients interpret it.
///
/// A node never reads this. It stores the tag as an opaque byte, so a new kind
/// is a client-side change and not a network upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PointerTargetKind {
    /// An immutable content-addressed chunk.
    Chunk,
    /// Another pointer, which is how handover-by-indirection is expressed.
    Pointer,
}

impl PointerTargetKind {
    /// Wire tag for this kind.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Chunk => 0,
            Self::Pointer => 1,
        }
    }

    /// Interpret a wire tag, if it names a kind this build knows.
    ///
    /// Returns `None` for anything else rather than an error: an unrecognised
    /// tag is a target this client cannot follow, not a malformed record.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Chunk),
            1 => Some(Self::Pointer),
            _ => None,
        }
    }
}

/// A kind tag plus the address it refers to.
///
/// The tag is carried and signed but never interpreted by a storing node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PointerTarget {
    /// The raw kind tag, meaningful only to clients.
    kind_tag: u8,
    /// The address pointed at.
    pub address: XorName,
}

impl PointerTarget {
    /// Build a target of a known kind.
    #[must_use]
    pub const fn new(kind: PointerTargetKind, address: XorName) -> Self {
        Self {
            kind_tag: kind.tag(),
            address,
        }
    }

    /// Build a target from a raw tag, including one this build does not know.
    #[must_use]
    pub const fn from_raw_tag(kind_tag: u8, address: XorName) -> Self {
        Self { kind_tag, address }
    }

    /// The raw kind tag as carried on the wire.
    #[must_use]
    pub const fn kind_tag(&self) -> u8 {
        self.kind_tag
    }

    /// The kind, if this build recognises the tag.
    #[must_use]
    pub const fn kind(&self) -> Option<PointerTargetKind> {
        PointerTargetKind::from_tag(self.kind_tag)
    }

    /// Encode to its [`TARGET_WIRE_LEN`] wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TARGET_WIRE_LEN] {
        let mut out = [0u8; TARGET_WIRE_LEN];
        if let Some((tag, address)) = out.split_first_mut() {
            *tag = self.kind_tag;
            address.copy_from_slice(&self.address);
        }
        out
    }

    /// Decode from wire bytes.
    ///
    /// Only the length can fail: every tag value is accepted, because a node
    /// stores the target without interpreting it.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (tag, rest) = bytes.split_first()?;
        if rest.len() != XORNAME_LEN {
            return None;
        }
        let mut address = [0u8; XORNAME_LEN];
        address.copy_from_slice(rest);
        Some(Self {
            kind_tag: *tag,
            address,
        })
    }
}

// =============================================================================
// Merge order
// =============================================================================

/// The merge rule's comparison key: larger wins.
///
/// One type so that every comparison — an arriving record against a parsed one,
/// or against a store's index entry — is literally the same ordering. Deriving
/// `Ord` over the fields in declaration order is what encodes the rule:
/// `counter` first, then the target, inverted so that *smaller* target bytes
/// rank higher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MergeRank {
    /// The update counter. Larger wins.
    counter: u64,
    /// The encoded target, inverted: smaller bytes win.
    target: std::cmp::Reverse<[u8; TARGET_WIRE_LEN]>,
}

// =============================================================================
// State
// =============================================================================

/// The parts of a record that determine its authenticated state.
///
/// Parsed from the body alone, so obtaining one costs no signature
/// verification. That is what lets a node recognise a re-submission of what it
/// already holds and stop before doing expensive work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerState {
    /// The authenticated-state identifier, derived from the signed body.
    pub state_id: XorName,
    /// The address the record belongs at.
    pub address: XorName,
    /// The update counter, the merge rule's first key.
    pub counter: u64,
    /// The target, whose bytes are the merge rule's second key.
    pub target: PointerTarget,
}

impl PointerState {
    /// Parse the state out of a record's bytes without verifying its signature.
    ///
    /// Checks length, format version and structure only. A `PointerState` says
    /// what a record *claims*; only [`Pointer::from_bytes`] establishes that
    /// the claim is signed.
    ///
    /// # Errors
    ///
    /// Returns [`PointerError`] for a record of the wrong length, an unknown
    /// format version, or an unparseable owner key.
    pub fn parse(bytes: &[u8]) -> Result<Self, PointerError> {
        Self::parse_with_owner(bytes).map(|(state, _)| state)
    }

    /// As [`Self::parse`], also returning the decoded owner key.
    fn parse_with_owner(bytes: &[u8]) -> Result<(Self, MlDsaPublicKey), PointerError> {
        if bytes.len() != POINTER_WIRE_LEN {
            return Err(PointerError::WrongLength(bytes.len()));
        }
        let version = bytes
            .first()
            .copied()
            .ok_or(PointerError::WrongLength(bytes.len()))?;
        if version != POINTER_FORMAT_VERSION {
            return Err(PointerError::UnknownFormatVersion(version));
        }

        let owner_bytes = bytes
            .get(OWNER_OFFSET..COUNTER_OFFSET)
            .ok_or(PointerError::WrongLength(bytes.len()))?;
        let owner = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, owner_bytes)
            .map_err(|e| PointerError::InvalidOwnerKey(e.to_string()))?;

        let counter_bytes: [u8; 8] = bytes
            .get(COUNTER_OFFSET..TARGET_OFFSET)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(PointerError::WrongLength(bytes.len()))?;

        let target = bytes
            .get(TARGET_OFFSET..POINTER_BODY_LEN)
            .and_then(PointerTarget::from_bytes)
            .ok_or(PointerError::WrongLength(bytes.len()))?;

        let body = bytes
            .get(..POINTER_BODY_LEN)
            .ok_or(PointerError::WrongLength(bytes.len()))?;

        Ok((
            Self {
                state_id: state_id_for_body(body),
                address: pointer_address(&owner),
                counter: u64::from_be_bytes(counter_bytes),
                target,
            },
            owner,
        ))
    }

    /// The comparison key for [`Self::replaces`].
    #[must_use]
    fn rank(&self) -> MergeRank {
        MergeRank {
            counter: self.counter,
            target: std::cmp::Reverse(self.target.to_bytes()),
        }
    }

    /// Whether `self` replaces `other` under the merge rule.
    ///
    /// ```text
    /// 1. larger counter
    /// 2. smaller target bytes
    /// ```
    ///
    /// A total order on the states of **one** pointer address. Records of
    /// different owners are not comparable and neither replaces the other.
    ///
    /// Equal state never replaces, whatever the signature bytes: ML-DSA signing
    /// is randomized, so one authenticated state has unboundedly many valid
    /// encodings, and ordering records by their bytes would let an owner sign
    /// one paid state repeatedly, sort worst-first and have every submission
    /// win — unbounded storage, replication and audit work for a single
    /// payment.
    ///
    /// At `counter == u64::MAX` the order still holds, and that has a
    /// consequence worth stating plainly: the pointer is **not frozen**. The
    /// counter can no longer advance, but equal counters are still resolved by
    /// target bytes, and *smaller* bytes win. So a terminal pointer can still
    /// be moved — but only ever toward smaller target bytes, and never back.
    /// See [`Pointer::next_counter`] for what that means for migration.
    #[must_use]
    pub fn replaces(&self, other: &Self) -> bool {
        self.address == other.address && self.rank() > other.rank()
    }
}

// =============================================================================
// Parsed-but-unverified record
// =============================================================================

/// Bytes that have been structurally parsed but not yet verified.
///
/// The bytes travel with their parse, so a caller cannot pair one record's
/// bytes with another's state. Only [`Pointer::verify_parsed`] consumes it, and
/// only that step establishes that the bytes are signed.
pub struct ParsedPointer {
    /// The record's canonical encoding.
    bytes: Vec<u8>,
    /// What those bytes claim.
    state: PointerState,
    /// The owner key decoded from those bytes.
    owner: MlDsaPublicKey,
}

impl std::fmt::Debug for ParsedPointer {
    /// Shows what the unverified bytes claim, not the bytes themselves.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedPointer")
            .field("address", &hex::encode(self.state.address))
            .field("counter", &self.state.counter)
            .finish_non_exhaustive()
    }
}

impl ParsedPointer {
    /// Parse `bytes`, without verifying the signature.
    ///
    /// # Errors
    ///
    /// As [`PointerState::parse`].
    pub fn parse(bytes: Vec<u8>) -> Result<Self, PointerError> {
        let (state, owner) = PointerState::parse_with_owner(&bytes)?;
        Ok(Self {
            bytes,
            state,
            owner,
        })
    }

    /// What the unverified bytes claim.
    #[must_use]
    pub const fn state(&self) -> &PointerState {
        &self.state
    }
}

// =============================================================================
// The record
// =============================================================================

/// A paid, mutable, owner-signed reference.
///
/// A value of this type has been through [`Pointer::from_bytes`], so its
/// signature covers exactly its body and its address derives from its owner.
#[derive(Clone)]
pub struct Pointer {
    /// Wire format discriminator. Signed, so it cannot be downgraded.
    version: u8,
    /// The owner's public key — the pointer's identity.
    ///
    /// The address is derived from the owner key alone, so a pointer is public-key
    /// addressed, and the key that verifies it travels with it: ML-DSA has no
    /// key recovery and a 1,952-byte key cannot be a 32-byte address.
    owner: MlDsaPublicKey,
    /// The merge rule's first key: a larger counter wins.
    ///
    /// [`Self::create`] starts at 0 and [`Self::update`] adds one, but nothing
    /// requires the next state to be exactly one on. The counter orders states;
    /// it does not meter them. Every stored state is paid for once, whatever
    /// its number, so a number that is skipped is never stored and owes nothing.
    counter: u64,
    /// What this points at: a chunk or another pointer. Opaque to a node.
    target: PointerTarget,
    /// The owner's signature over every field above.
    sig: MlDsaSignature,
}

impl std::fmt::Debug for Pointer {
    /// Shows what identifies the record, not its 5 KB of key and signature.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pointer")
            .field("address", &hex::encode(self.address()))
            .field("counter", &self.counter)
            .field("target_tag", &self.target.kind_tag())
            .field("target", &hex::encode(self.target.address))
            .field("state_id", &hex::encode(self.state_id()))
            .finish_non_exhaustive()
    }
}

impl Pointer {
    /// Build and sign a pointer.
    ///
    /// # Errors
    ///
    /// Returns [`PointerError::SigningFailed`] if signing fails, or a parse
    /// error if the resulting record does not parse, which would be a bug here
    /// rather than bad input.
    pub fn sign(
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        counter: u64,
        target: PointerTarget,
    ) -> Result<Self, PointerError> {
        let body = encode_body(POINTER_FORMAT_VERSION, owner, counter, target)?;
        let signature = ml_dsa_65()
            .sign_with_context(secret_key, &body, SIGNING_CONTEXT)
            .map_err(|e| PointerError::SigningFailed(e.to_string()))?;
        let mut bytes = body;
        bytes.extend_from_slice(&signature.to_bytes());
        Self::from_bytes(&bytes)
    }

    /// Create a pointer at counter 0.
    ///
    /// # Errors
    ///
    /// As [`Self::sign`].
    pub fn create(
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        target: PointerTarget,
    ) -> Result<Self, PointerError> {
        Self::sign(secret_key, owner, 0, target)
    }

    /// Sign the update that follows this one: `counter + 1`, new target.
    ///
    /// One past this record is the smallest counter that replaces it, and so
    /// the natural next state. A larger one would replace it just as well.
    ///
    /// # Errors
    ///
    /// Returns [`PointerError::CounterExhausted`] at `u64::MAX`, otherwise as
    /// [`Self::sign`].
    pub fn update(
        &self,
        secret_key: &MlDsaSecretKey,
        target: PointerTarget,
    ) -> Result<Self, PointerError> {
        Self::sign(secret_key, &self.owner, self.next_counter()?, target)
    }

    /// Parse and fully validate a record.
    ///
    /// Checks, cheapest first: length, format version, structure, then the
    /// signature. A returned `Pointer` is structurally valid and correctly
    /// signed by the key it carries; it says nothing about payment, which is a
    /// separate external check.
    ///
    /// # Errors
    ///
    /// Returns [`PointerError`] for a malformed record or one whose signature
    /// does not verify.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PointerError> {
        Self::verify_parsed(ParsedPointer::parse(bytes.to_vec())?)
    }

    /// Verify a record that has already been parsed.
    ///
    /// Decoding an ML-DSA public key is not free, and the request path parses
    /// before it decides whether verification is worth doing at all. This lets
    /// it hand over what it already has instead of decoding a second time.
    ///
    /// # Errors
    ///
    /// As [`Self::from_bytes`].
    pub fn verify_parsed(parsed: ParsedPointer) -> Result<Self, PointerError> {
        let ParsedPointer {
            bytes,
            state,
            owner,
        } = parsed;

        let body = bytes
            .get(..POINTER_BODY_LEN)
            .ok_or(PointerError::WrongLength(bytes.len()))?;
        let signature_bytes = bytes
            .get(POINTER_BODY_LEN..)
            .ok_or(PointerError::WrongLength(bytes.len()))?;
        let signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, signature_bytes)
            .map_err(|e| PointerError::InvalidSignatureFormat(e.to_string()))?;

        let valid = ml_dsa_65()
            .verify_with_context(&owner, body, &signature, SIGNING_CONTEXT)
            .map_err(|e| PointerError::InvalidSignatureFormat(e.to_string()))?;
        if !valid {
            return Err(PointerError::SignatureInvalid);
        }

        Ok(Self {
            version: POINTER_FORMAT_VERSION,
            owner,
            counter: state.counter,
            target: state.target,
            sig: signature,
        })
    }

    /// The canonical encoding of this record.
    ///
    /// Re-encoded from the fields rather than cached. Every field is
    /// fixed-width with no optionality, so there is exactly one encoding and
    /// this is always byte-identical to what was signed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.sig.to_bytes());
        out
    }

    /// The signed body: every field the signature covers.
    fn body(&self) -> Vec<u8> {
        encode_body(self.version, &self.owner, self.counter, self.target)
            .unwrap_or_else(|_| Vec::with_capacity(POINTER_BODY_LEN))
    }

    /// The owner's public key. Fixed for the pointer's life.
    #[must_use]
    pub const fn owner(&self) -> &MlDsaPublicKey {
        &self.owner
    }

    /// The signed state this record carries.
    ///
    /// Derived, not stored: the identifiers are hashes of fields already here.
    #[must_use]
    pub fn state(&self) -> PointerState {
        PointerState {
            state_id: self.state_id(),
            address: self.address(),
            counter: self.counter,
            target: self.target,
        }
    }

    /// The update counter.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// What this pointer points at.
    #[must_use]
    pub const fn target(&self) -> PointerTarget {
        self.target
    }

    /// The address this record belongs at, derived from the owner key.
    #[must_use]
    pub fn address(&self) -> XorName {
        pointer_address(&self.owner)
    }

    /// The authenticated-state identifier, derived from the signed body.
    ///
    /// Names the state rather than the encoding, so two records carrying
    /// different valid signatures over one state share a `state_id`. This is
    /// what sync hints carry and what a quote is paid against.
    #[must_use]
    pub fn state_id(&self) -> XorName {
        state_id_for_body(&self.body())
    }

    /// The successor counter for an update to this pointer.
    ///
    /// # Errors
    ///
    /// Returns [`PointerError::CounterExhausted`] at `u64::MAX`.
    ///
    /// A pointer that must outlive its counter has to be migrated by an
    /// **earlier** update — one that retargets it at a fresh pointer while a
    /// successor counter still exists. A migration written *at* `u64::MAX` is
    /// not final: the counter is spent, so the only thing that still decides
    /// the merge is the target, and any record with smaller target bytes
    /// displaces it. A strictly larger counter is the one move nothing can
    /// answer, so migration must spend a counter it still has.
    pub fn next_counter(&self) -> Result<u64, PointerError> {
        self.counter
            .checked_add(1)
            .ok_or(PointerError::CounterExhausted)
    }

    /// Whether this pointer's counter is spent.
    ///
    /// `true` once the counter reaches `u64::MAX`. Note this does not mean the
    /// stored value can no longer change: a record at the same counter with
    /// smaller target bytes still wins. It means the *counter* can no longer
    /// answer such a record, which is why clients migrate before reaching this
    /// rather than on it.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.counter == u64::MAX
    }

    /// Whether `self` replaces `other` under the merge rule.
    ///
    /// See [`PointerState::replaces`], which is where the rule lives.
    #[must_use]
    pub fn replaces(&self, other: &Self) -> bool {
        self.state().replaces(&other.state())
    }
}

/// Encode the signed body of a pointer.
fn encode_body(
    version: u8,
    owner: &MlDsaPublicKey,
    counter: u64,
    target: PointerTarget,
) -> Result<Vec<u8>, PointerError> {
    let owner_bytes = owner.to_bytes();
    if owner_bytes.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        return Err(PointerError::InvalidOwnerKey(format!(
            "owner key must be {ML_DSA_65_PUBLIC_KEY_LEN} bytes, got {}",
            owner_bytes.len()
        )));
    }
    let mut body = Vec::with_capacity(POINTER_BODY_LEN);
    // The record's own version, not this build's: a record is re-encoded as
    // what was signed. Only `POINTER_FORMAT_VERSION` parses today, so the two
    // coincide — but the encoder must not be the thing that assumes it.
    body.push(version);
    body.extend_from_slice(&owner_bytes);
    body.extend_from_slice(&counter.to_be_bytes());
    body.extend_from_slice(&target.to_bytes());
    Ok(body)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "the crate guide allows these in tests"
)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> (MlDsaPublicKey, MlDsaSecretKey) {
        ml_dsa_65().generate_keypair_from_seed(&[seed; 32])
    }

    fn signed(seed: u8, counter: u64, target_byte: u8) -> Pointer {
        let (pk, sk) = keypair(seed);
        let target = PointerTarget::new(PointerTargetKind::Chunk, [target_byte; XORNAME_LEN]);
        Pointer::sign(&sk, &pk, counter, target).expect("sign")
    }

    #[test]
    fn sizes_match_the_design() {
        assert_eq!(POINTER_BODY_LEN, 1994);
        assert_eq!(POINTER_WIRE_LEN, 5303);
        assert_eq!(signed(1, 0, 0).to_bytes().len(), POINTER_WIRE_LEN);
    }

    #[test]
    fn roundtrips_and_validates() {
        let record = signed(1, 42, 7);
        let parsed = Pointer::from_bytes(&record.to_bytes()).expect("reparse");
        assert_eq!(parsed.counter(), 42);
        assert_eq!(parsed.address(), record.address());
        assert_eq!(parsed.state_id(), record.state_id());
    }

    #[test]
    fn a_tampered_record_does_not_verify() {
        let record = signed(1, 5, 5);
        let mut bytes = record.to_bytes();
        if let Some(byte) = bytes.get_mut(COUNTER_OFFSET + 7) {
            *byte ^= 1;
        }
        assert!(matches!(
            Pointer::from_bytes(&bytes),
            Err(PointerError::SignatureInvalid)
        ));
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let record = signed(1, 1, 1);
        let mut bytes = record.to_bytes();
        if let Some(byte) = bytes.first_mut() {
            *byte = 2;
        }
        assert!(matches!(
            Pointer::from_bytes(&bytes),
            Err(PointerError::UnknownFormatVersion(2))
        ));
    }

    #[test]
    fn the_format_version_reaches_the_paid_identifier() {
        // A record differing only in its version byte is a different state and
        // must be paid for separately. Without this a future version could
        // reuse a receipt bought for version 1.
        let record = signed(1, 3, 3);
        let mut body = record
            .to_bytes()
            .get(..POINTER_BODY_LEN)
            .expect("body")
            .to_vec();
        let baseline = state_id_for_body(&body);
        assert_eq!(baseline, record.state_id());

        for version in 0u8..=255 {
            if version == POINTER_FORMAT_VERSION {
                continue;
            }
            if let Some(byte) = body.first_mut() {
                *byte = version;
            }
            assert_ne!(
                state_id_for_body(&body),
                baseline,
                "version {version} must not share version 1's paid identifier"
            );
        }
    }

    #[test]
    fn different_owners_are_not_comparable() {
        let mine = signed(1, 1, 9);
        let theirs = signed(2, 500, 0);
        assert!(!mine.replaces(&theirs));
        assert!(!theirs.replaces(&mine));
    }

    #[test]
    fn the_counter_is_terminal_at_its_maximum() {
        let ordinary = signed(1, 0, 0);
        assert!(!ordinary.is_terminal());
        assert_eq!(ordinary.next_counter().expect("next"), 1);

        let terminal = signed(1, u64::MAX, 0);
        assert!(terminal.is_terminal());
        assert_eq!(terminal.next_counter(), Err(PointerError::CounterExhausted));
        assert!(terminal.next_counter().is_err());
    }

    #[test]
    fn nothing_out_ranks_a_terminal_counter() {
        // The migration rule: at u64::MAX no later record can win, so a pointer
        // that must outlive its counter has to be retargeted *before* the
        // terminal update, not on it.
        let terminal = signed(1, u64::MAX, 5);
        for counter in [0u64, 1, 42, u64::MAX - 1] {
            let earlier = signed(1, counter, 0);
            assert!(
                !earlier.replaces(&terminal),
                "counter {counter} must not replace a terminal pointer"
            );
            assert!(terminal.replaces(&earlier));
        }
    }

    #[test]
    fn a_terminal_counter_still_resolves_equal_counter_conflicts() {
        // The order does not degenerate at the maximum: two records at
        // u64::MAX with different targets still resolve deterministically, so
        // replicas cannot split there.
        let low_target = signed(1, u64::MAX, 1);
        let high_target = signed(1, u64::MAX, 2);
        assert!(low_target.replaces(&high_target), "smaller target wins");
        assert!(!high_target.replaces(&low_target));
    }

    #[test]
    fn create_starts_at_zero_and_update_adds_one() {
        let (pk, sk) = keypair(20);
        let target = |b: u8| PointerTarget::new(PointerTargetKind::Chunk, [b; XORNAME_LEN]);

        let created = Pointer::create(&sk, &pk, target(1)).expect("create");
        assert_eq!(created.counter(), 0);

        let first = created.update(&sk, target(2)).expect("update");
        assert_eq!(first.counter(), 1);
        assert!(first.replaces(&created));

        let second = first.update(&sk, target(3)).expect("update");
        assert_eq!(second.counter(), 2);
        assert!(second.replaces(&first));
    }

    #[test]
    fn any_larger_counter_replaces_so_counters_may_skip() {
        // The counter orders states; it does not meter them. Each stored state
        // is paid for once whatever its number, so a skipped number is never
        // stored and owes nothing.
        let held = signed(21, 5, 7);
        for later in [6u64, 7, 99, u64::MAX] {
            assert!(
                signed(21, later, 7).replaces(&held),
                "counter {later} must replace counter 5"
            );
        }
        for earlier in [0u64, 4] {
            assert!(
                !signed(21, earlier, 7).replaces(&held),
                "counter {earlier} must not replace counter 5"
            );
        }
    }

    #[test]
    fn a_fork_at_one_counter_resolves_by_target_and_any_later_counter_heals_it() {
        // Two records at one counter are a fork. Every node that sees both
        // keeps the smaller target, and a record at any later counter replaces
        // whichever side a node was left holding.
        let smaller = signed(25, 5, 1);
        let larger = signed(25, 5, 9);
        assert!(smaller.replaces(&larger), "smaller target bytes win");
        assert!(!larger.replaces(&smaller));

        for later in [6u64, 50] {
            let healed = signed(25, later, 9);
            assert!(healed.replaces(&smaller));
            assert!(healed.replaces(&larger));
        }
    }

    #[test]
    fn a_terminal_pointer_cannot_be_updated() {
        let (pk, sk) = keypair(24);
        let target = PointerTarget::new(PointerTargetKind::Chunk, [1; XORNAME_LEN]);
        let terminal = Pointer::sign(&sk, &pk, u64::MAX, target).expect("sign");
        assert!(
            terminal.update(&sk, target).is_err(),
            "the counter must not wrap around into a fresh-looking pointer"
        );
    }

    /// Re-encoding must be byte-identical to what was signed.
    ///
    /// This is what lets the record hold its five fields and nothing else: the
    /// encoding is fixed-width with no optionality, so there is exactly one
    /// byte sequence for a given record and caching it would buy nothing. If
    /// this ever fails, the cache has to come back.
    #[test]
    fn re_encoding_is_byte_identical() {
        let (pk, sk) = keypair(30);
        for counter in [0u64, 1, 42, u64::MAX] {
            for tag in [0u8, 1, 200] {
                let target = PointerTarget::from_raw_tag(tag, [tag; XORNAME_LEN]);
                let signed = Pointer::sign(&sk, &pk, counter, target).expect("sign");
                let wire = signed.to_bytes();

                // Parsed from the wire, re-encoded, identical.
                let parsed = Pointer::from_bytes(&wire).expect("parse");
                assert_eq!(parsed.to_bytes(), wire, "counter {counter}, tag {tag}");

                // And still verifies, which is the property that actually matters.
                assert!(Pointer::from_bytes(&parsed.to_bytes()).is_ok());
            }
        }
    }

    #[test]
    fn equal_state_never_replaces() {
        let variants: Vec<Pointer> = (0..8).map(|_| signed(1, 7, 3)).collect();
        for a in &variants {
            for b in &variants {
                assert!(!a.replaces(b));
                assert_eq!(a.state_id(), b.state_id());
            }
        }
    }

    #[test]
    fn the_obvious_chunk_preimages_miss_both_pointer_identities() {
        // A chunk's address is BLAKE3 over its content, so a hash of a prefix
        // and a key was reachable by anyone who could write that prefix as a
        // chunk: they could squat an owner's address before it was created, or
        // buy a pointer and a chunk with one payment. These are the preimages
        // that construction handed out. Nothing here proves no content exists —
        // that is a preimage assumption, not a test.
        let (pk, sk) = keypair(77);
        let record = Pointer::create(
            &sk,
            &pk,
            PointerTarget::new(PointerTargetKind::Chunk, [3; XORNAME_LEN]),
        )
        .expect("create");

        let address_preimage = [b"autonomi.pointer.address.v1".as_slice(), &pk.to_bytes()].concat();
        assert_ne!(
            *blake3::hash(&address_preimage).as_bytes(),
            record.address(),
            "a chunk holding this content must not land on the pointer's address"
        );

        let body = record.to_bytes();
        let body = body.get(..POINTER_BODY_LEN).expect("body");
        let state_preimage = [b"autonomi.pointer.state.v1".as_slice(), body].concat();
        assert_ne!(
            *blake3::hash(&state_preimage).as_bytes(),
            record.state_id(),
            "a chunk holding this content must not land on the paid identifier"
        );

        // Nor does the bare key, the bare body, or the context alone.
        for content in [
            pk.to_bytes().as_slice(),
            body,
            b"autonomi.pointer.address.v1",
        ] {
            let address = *blake3::hash(content).as_bytes();
            assert_ne!(address, record.address());
            assert_ne!(address, record.state_id());
        }
    }

    #[test]
    fn the_rule_is_a_strict_order_so_no_fold_depends_on_arrival_order() {
        // Nodes and clients both pick a winner by folding `replaces` over
        // whatever arrives. That fold gives the same answer whatever the order
        // exactly when the rule is a strict total order on one address: never
        // both ways round, always one way for distinct states, and transitive.
        let records = [
            signed(1, 0, 9),
            signed(1, 2, 1),
            signed(1, 5, 1),
            signed(1, 5, 2),
        ];
        for a in &records {
            assert!(!a.replaces(a), "an equal state never replaces");
            for b in &records {
                assert!(
                    !(a.replaces(b) && b.replaces(a)),
                    "two records cannot each replace the other"
                );
                assert!(
                    a.replaces(b) || b.replaces(a) || a.state_id() == b.state_id(),
                    "distinct states are always ordered"
                );
                for c in &records {
                    assert!(
                        !(a.replaces(b) && b.replaces(c)) || a.replaces(c),
                        "the order is transitive"
                    );
                }
            }
        }
    }
}
