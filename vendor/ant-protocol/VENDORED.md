# Vendored from crates.io (ant-protocol 5.0.0, sha256 e4ad739a...).
# The changes from upstream:
# - src/payment/pricing.rs: PRICE_MULTIPLIER (32) scales every price on the curve.
# - src/payment/pricing.rs: record_weight, weighted_amount and weight_total, with RecordWeight and their constants, price a
#   record by its size class. No quote or payment path uses them yet; the tests of the repository
#   that vendors this copy pin them.
# - Root payment proofs: PROOF_TAG_ROOT (0x03) in src/chunk.rs; ProofType::Root, RootPaymentProof,
#   serialize_root_proof and deserialize_root_proof in src/payment/proof.rs, exported as the others
#   are. ProofType is no longer #[non_exhaustive], so every match on it names each type.
