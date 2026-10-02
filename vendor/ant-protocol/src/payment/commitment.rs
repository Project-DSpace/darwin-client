//! The signed storage commitment — shared between node and client (ADR-0004).
//!
//! ADR-0004 makes a quote's price a function of the node's audited storage
//! commitment, and requires the **client** to fully verify that commitment
//! before paying ("the client pays nothing it cannot resolve" — the ceiling's
//! load-bearing wall). To do that the client needs the commitment type, its
//! pin (hash), and its signature/peer-binding check — exactly the pieces here.
//!
//! This is the **single source of truth** for the commitment wire type and its
//! verification: `ant-node` re-exports [`StorageCommitment`], [`commitment_hash`],
//! [`verify_commitment_signature`], and [`MAX_COMMITMENT_KEY_COUNT`] from this
//! module so the node (gossip/audit) and the client (resolve-before-pay) can
//! never disagree on what a valid commitment is or what pin it hashes to.
//!
//! Only the *verification* surface lives here. The Merkle tree, inclusion
//! paths, and signing live in `ant-node` (the responder/auditor own those);
//! the client never builds or signs a commitment, it only verifies one.

use blake3::Hasher;
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};
use serde::{Deserialize, Serialize};

/// Domain-separation tag for the commitment signature.
///
/// Signed payload is verified under this context tag.
pub const DOMAIN_COMMITMENT: &[u8] = b"autonomi.ant.replication.storage_commitment.v1";

/// Domain-separation tag for the auditor's pin: BLAKE3 over (this tag ||
/// canonical commitment blob).
pub const DOMAIN_COMMITMENT_HASH: &[u8] = b"autonomi.ant.replication.commitment_hash.v1";

/// Maximum number of keys a single commitment may cover.
///
/// Bounds the Merkle path depth and responder-side tree memory. A node storing
/// more keys than this would need to split its claim. The client rejects any
/// quote whose `committed_key_count` exceeds this before paying, exactly as the
/// node does.
pub const MAX_COMMITMENT_KEY_COUNT: u32 = 1_000_000;

/// Maximum serialized size of a single commitment sidecar blob (ADR-0004).
///
/// A well-formed `StorageCommitment` is ~5.3 KiB (root 32 + `key_count` 4 +
/// `peer_id` 32 + pubkey 1952 + signature 3293 + serde framing). 8 KiB leaves
/// generous headroom while bounding the deserialize/verify work a malicious
/// quote responder or client can force on the hot verification path. A sidecar
/// larger than this is rejected before any parse attempt.
pub const MAX_COMMITMENT_SIDECAR_BYTES: usize = 8 * 1024;

/// Signed storage commitment.
///
/// Piggybacked on neighbour-sync gossip and shipped alongside a quote (ADR-0004).
/// The signature commits to the Merkle root, key count, sender peer ID, **and
/// the sender's ML-DSA-65 public key** under [`DOMAIN_COMMITMENT`].
///
/// Embedding the public key lets any receiver (including the paying client)
/// verify the signature without an external `PeerId → MlDsaPublicKey` lookup.
/// Binding the public key in the signed payload prevents a key-swap attack.
///
/// Wire size ≈ 5.3 KiB (root 32 B + `key_count` 4 B + `peer_id` 32 B + pubkey
/// 1952 B + signature 3293 B).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageCommitment {
    /// Merkle root over the responder's claimed keys.
    pub root: [u8; 32],
    /// Number of leaves committed over.
    pub key_count: u32,
    /// Sender peer ID, bound to the signature.
    pub sender_peer_id: [u8; 32],
    /// Sender's ML-DSA-65 public key bytes (1952 bytes). Embedded so receivers
    /// can verify the signature without a separate pubkey directory. Bound by
    /// the signature.
    pub sender_public_key: Vec<u8>,
    /// ML-DSA-65 signature over canonical commitment fields. 3293 bytes.
    pub signature: Vec<u8>,
}

/// The pin: `BLAKE3(DOMAIN_COMMITMENT_HASH || postcard(commitment))`.
///
/// Equal commitments produce equal hashes; any change to `root`, `key_count`,
/// peer ID, pubkey, or signature changes the hash. A quote pins a commitment by
/// this value; resolving the quote means finding a commitment that hashes to
/// the pin.
///
/// # Errors
///
/// Returns `None` only if postcard fails to serialize the commitment — not
/// reachable for a well-formed ML-DSA-65 commitment. Callers treat `None` as a
/// malformed commitment and drop it.
#[must_use]
pub fn commitment_hash(c: &StorageCommitment) -> Option<[u8; 32]> {
    let serialized = postcard::to_allocvec(c).ok()?;
    let mut h = Hasher::new();
    h.update(DOMAIN_COMMITMENT_HASH);
    h.update(&serialized);
    Some(*h.finalize().as_bytes())
}

/// Canonical bytes the ML-DSA signature covers: the commitment fields minus the
/// signature itself.
///
/// `sender_public_key` is length-prefixed and included so an adversary cannot
/// keep the body and re-sign under a different key.
#[must_use]
pub fn commitment_signed_payload(
    root: &[u8; 32],
    key_count: u32,
    sender_peer_id: &[u8; 32],
    sender_public_key: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 4 + 32 + 4 + sender_public_key.len());
    v.extend_from_slice(root);
    v.extend_from_slice(&key_count.to_le_bytes());
    v.extend_from_slice(sender_peer_id);
    let pk_len = u32::try_from(sender_public_key.len()).unwrap_or(u32::MAX);
    v.extend_from_slice(&pk_len.to_le_bytes());
    v.extend_from_slice(sender_public_key);
    v
}

/// Verify a commitment's ML-DSA-65 signature against its **embedded** public
/// key. Does NOT check the peer binding (`BLAKE3(pubkey) == sender_peer_id`) —
/// callers that need it (the client, the node) check it separately so the same
/// function serves both the "trust the embedded key" and "bind to a peer" uses.
#[must_use]
pub fn verify_commitment_signature(c: &StorageCommitment) -> bool {
    let Ok(public_key) = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &c.sender_public_key)
    else {
        return false;
    };
    let payload = commitment_signed_payload(
        &c.root,
        c.key_count,
        &c.sender_peer_id,
        &c.sender_public_key,
    );
    let Ok(sig) = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &c.signature) else {
        return false;
    };
    ml_dsa_65()
        .verify_with_context(&public_key, &payload, &sig, DOMAIN_COMMITMENT)
        .unwrap_or(false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use saorsa_pqc::api::sig::ml_dsa_65;

    /// Build a genuinely-signed commitment (fresh ML-DSA-65 keypair, signed over
    /// the exact `commitment_signed_payload` under `DOMAIN_COMMITMENT`) — the same
    /// thing the node produces. Returns the commitment and the keypair's public
    /// bytes so tamper tests can key-swap.
    fn signed_commitment(root: [u8; 32], key_count: u32, peer_id: [u8; 32]) -> StorageCommitment {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let payload = commitment_signed_payload(&root, key_count, &peer_id, &pk_bytes);
        let sig = ml_dsa_65()
            .sign_with_context(&sk, &payload, DOMAIN_COMMITMENT)
            .unwrap();
        StorageCommitment {
            root,
            key_count,
            sender_peer_id: peer_id,
            sender_public_key: pk_bytes,
            signature: sig.to_bytes(),
        }
    }

    /// A malformed commitment (bad pubkey / signature) fails verification
    /// rather than panicking — the client runs this on untrusted bytes.
    #[test]
    fn verify_rejects_malformed_without_panic() {
        let c = StorageCommitment {
            root: [0u8; 32],
            key_count: 1,
            sender_peer_id: [0u8; 32],
            sender_public_key: vec![0u8; 10],
            signature: vec![0u8; 10],
        };
        assert!(!verify_commitment_signature(&c));
        // hash is still computable over any well-formed struct.
        assert!(commitment_hash(&c).is_some());
    }

    /// The pin is deterministic and changes when any field changes.
    #[test]
    fn commitment_hash_is_deterministic_and_field_sensitive() {
        let c = StorageCommitment {
            root: [1u8; 32],
            key_count: 5,
            sender_peer_id: [2u8; 32],
            sender_public_key: vec![3u8; 20],
            signature: vec![4u8; 20],
        };
        let h1 = commitment_hash(&c).unwrap();
        let h2 = commitment_hash(&c).unwrap();
        assert_eq!(h1, h2, "same commitment -> same pin");

        let mut c2 = c.clone();
        c2.key_count = 6;
        assert_ne!(
            commitment_hash(&c2).unwrap(),
            h1,
            "changing key_count must change the pin"
        );
    }

    /// A correctly-signed commitment verifies. Without this, a regression that
    /// made `verify_commitment_signature` always return `false` (or ignore the
    /// signature) would pass every other test in this module.
    #[test]
    fn verify_accepts_a_correctly_signed_commitment() {
        let c = signed_commitment([7u8; 32], 42, [9u8; 32]);
        assert!(
            verify_commitment_signature(&c),
            "a genuinely signed commitment must verify"
        );
    }

    /// The signature covers `root`, `key_count`, `peer_id`, and the embedded
    /// pubkey — mutating any of them after signing must fail verification. This
    /// is the ADR-0004 "the fields are covered by the signature" invariant.
    #[test]
    fn verify_rejects_any_field_tampered_after_signing() {
        // key_count
        let mut c = signed_commitment([1u8; 32], 100, [2u8; 32]);
        c.key_count = c.key_count.wrapping_add(1);
        assert!(
            !verify_commitment_signature(&c),
            "tampered key_count must fail"
        );

        // root
        let mut c = signed_commitment([1u8; 32], 100, [2u8; 32]);
        c.root[0] ^= 0xff;
        assert!(!verify_commitment_signature(&c), "tampered root must fail");

        // sender_peer_id
        let mut c = signed_commitment([1u8; 32], 100, [2u8; 32]);
        c.sender_peer_id[0] ^= 0xff;
        assert!(
            !verify_commitment_signature(&c),
            "tampered peer_id must fail"
        );

        // key-swap: keep the body + signature, swap in a different valid pubkey.
        // The pubkey is bound into the signed payload, so this must fail.
        let mut c = signed_commitment([1u8; 32], 100, [2u8; 32]);
        let (other_pk, _) = ml_dsa_65().generate_keypair().unwrap();
        c.sender_public_key = other_pk.to_bytes();
        assert!(
            !verify_commitment_signature(&c),
            "swapping the embedded pubkey must fail"
        );
    }
}
