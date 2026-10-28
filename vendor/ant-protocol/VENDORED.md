# Vendored from crates.io (ant-protocol 5.0.0, sha256 e4ad739a...).
# The changes from upstream, in src/payment/pricing.rs and src/chunk.rs:
# - The price curve: calculate_price is BASELINE + 9 × BASELINE × (n / 2,000)², BASELINE 0.1396736 DARWIN,
#   100 DARWIN per 10^9 bytes of full chunks at an empty node (Dan, 2026-10-28). calculate_price_legacy,
#   derive_records_stored_from_price_legacy and price_band_legacy keep the earlier curve, upstream's
#   constants × 32 with divisor 6,000, accepted beside it; price_in_band accepts a price in either
#   curve's band.
# - record_weight, weighted_amount and weight_total, with RecordWeight and their constants, price a
#   record by its size class, and band_bottom_count, price_band and price_in_band give the prices a
#   quote may carry; the tests of the repository that vendors this copy pin them.
# - CURRENT_SETTLEMENT_VERSION is 2: a payment covers its record's size class.
#   MIN_SUPPORTED_SETTLEMENT_VERSION stays 1.
