# Vendored from crates.io (ant-protocol 5.0.0, sha256 e4ad739a...).
# The changes from upstream, in src/payment/pricing.rs, src/payment/proof.rs and src/chunk.rs:
# - PRICE_MULTIPLIER (32) scales every price on the curve.
# - record_weight, weighted_amount and weight_total, with RecordWeight and their constants, price a
#   record by its size class, and band_bottom_count, price_band and price_in_band give the prices a
#   quote may carry; the tests of the repository that vendors this copy pin them.
# - CURRENT_SETTLEMENT_VERSION is 2: a payment covers its record's size class.
#   MIN_SUPPORTED_SETTLEMENT_VERSION stays 1.
# - Root payment proofs: PROOF_TAG_ROOT (0x03) in src/chunk.rs; ProofType::Root, RootPaymentProof,
#   serialize_root_proof and deserialize_root_proof in src/payment/proof.rs, exported as the others
#   are. ProofType is no longer #[non_exhaustive], so every match on it names each type.
# - src/chunk.rs: CURRENT_SETTLEMENT_VERSION is 3, which means root proofs are accepted beside
#   single-node proofs; MIN_SUPPORTED_SETTLEMENT_VERSION stays 1.
