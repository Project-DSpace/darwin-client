# Vendored from crates.io (ant-protocol 5.0.0, sha256 e4ad739a...).
# The changes from upstream, all in src/payment/pricing.rs:
# - PRICE_MULTIPLIER (32) scales every price on the curve.
# - record_weight, weighted_amount and weight_total, with RecordWeight and their constants, price a
#   record by its size class. No quote or payment path uses them yet; the tests of the repository
#   that vendors this copy pin them.
