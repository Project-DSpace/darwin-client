# Vendored from crates.io (ant-protocol 5.0.0, sha256 e4ad739a...).
# The changes from upstream, in src/payment/pricing.rs, src/payment/proof.rs, src/payment/mod.rs,
# src/lib.rs and src/chunk.rs:
# - The price curve: baseline 0.1396736 DARWIN, coefficient 9 × baseline, divisor 2,000 (Dan,
#   2026-10-28: 100 DARWIN per GB on empty nodes, D = 2,000). calculate_price_legacy,
#   price_band_legacy, price_in_band_legacy and price_in_accepted_band keep the previous curve,
#   upstream's × 32 (LEGACY_PRICE_MULTIPLIER), accepted beside it.
# - record_weight, weighted_amount and weight_total, with RecordWeight and their constants, price a
#   record by its size class, and band_bottom_count, price_band and price_in_band give the prices a
#   quote may carry; the tests of the repository that vendors this copy pin them.
# - Settlement version 2: a payment covers its record's size class.
# - Root payment proofs: PROOF_TAG_ROOT (0x03) in src/chunk.rs; ProofType::Root, RootPaymentProof,
#   serialize_root_proof and deserialize_root_proof in src/payment/proof.rs, exported as the others
#   are. ProofType is no longer #[non_exhaustive], so every match on it names each type.
# - src/chunk.rs: CURRENT_SETTLEMENT_VERSION is 3, which means root proofs are accepted beside
#   single-node proofs; MIN_SUPPORTED_SETTLEMENT_VERSION stays 1.
