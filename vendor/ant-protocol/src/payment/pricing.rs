//! Quadratic pricing with a baseline floor.
//!
//! Formula: `price_per_chunk_ANT(n) = BASELINE + K × (n / D)²`
//!
//! The non-zero `BASELINE` makes empty nodes charge a meaningful spam-barrier
//! price, and `K` is anchored so per-GB USD pricing matches real-world targets
//! at the current ~$0.10/ANT token price. An earlier formula produced ~$25/GB
//! at the lower stable boundary and ~$0/GB when nodes were empty — both
//! unreasonable.
//!
//! This is the **single source of truth** both the node (when pricing a quote)
//! and the client (when verifying ADR-0004's forced price before paying) must
//! agree on. It lives here, in the shared wire/contract crate, so the two sides
//! can never drift: `ant-node` re-exports [`calculate_price`] from this module
//! rather than defining its own.
//!
//! ## Parameters
//!
//! | Constant  | Value         | Role                                            |
//! |-----------|---------------|-------------------------------------------------|
//! | BASELINE  | 0.00390625 ANT| Price at empty (bootstrap-phase spam barrier)   |
//! | K         | 0.03515625 ANT| Quadratic coefficient                           |
//! | D         | 6000          | Lower stable boundary (records stored)          |

use evmlib::common::Amount;

/// Lower stable boundary of the quadratic curve, in records stored.
const PRICING_DIVISOR: u128 = 6000;

/// `PRICING_DIVISOR²`, precomputed to avoid repeated multiplication.
const DIVISOR_SQUARED: u128 = PRICING_DIVISOR * PRICING_DIVISOR;

/// Baseline price at empty / bootstrap-phase spam barrier.
///
/// `0.00390625 ANT × 10¹⁸ wei/ANT = 3_906_250_000_000_000 wei`.
/// Our network scales every price on Autonomi's curve by this factor
/// (`VENDORED.md` lists every change from upstream). Our network pays in
/// DARWIN instead of ANT, and costs what
/// Autonomi does in dollars when DARWIN's market cap is $1M (1B supply, so
/// $0.001 per DARWIN): the factor is ANT's dollar price × 1,000. Set
/// 2026-10-06 with ANT at $0.0319 (it was 7,381 for the Pons test token).
/// Below that market cap storage costs less than Autonomi's, above it more.
/// Changing it means rebuilding nodes and clients together.
const PRICE_MULTIPLIER: u128 = 32;

const PRICE_BASELINE_WEI: u128 = 3_906_250_000_000_000 * PRICE_MULTIPLIER;

/// Quadratic coefficient `K`.
///
/// `0.03515625 ANT × 10¹⁸ wei/ANT = 35_156_250_000_000_000 wei`.
const PRICE_COEFFICIENT_WEI: u128 = 35_156_250_000_000_000 * PRICE_MULTIPLIER;

/// Price increment per squared record after simplifying `PRICE_COEFFICIENT_WEI / DIVISOR_SQUARED`.
const PRICE_PER_RECORD_SQUARED_WEI: u128 = PRICE_COEFFICIENT_WEI / DIVISOR_SQUARED;

/// Derive the quoted record count from a quote price.
///
/// This is the inverse of [`calculate_price`]. It intentionally floors to the
/// nearest integer record count.
///
/// Saturates to `u64::MAX` for any price that would otherwise overflow `u64`.
/// This matters because the node verifier calls this on untrusted deserialized
/// `quote.price` values BEFORE signature verification: a panic here is a
/// pre-auth crash vector. Saturating leaves the delta check to reject the
/// quote as out-of-range without aborting the process.
#[must_use]
pub fn derive_records_stored_from_price(price: Amount) -> u64 {
    let baseline = Amount::from(PRICE_BASELINE_WEI);
    if price <= baseline {
        return 0;
    }

    let excess = price - baseline;
    let n_squared = excess / Amount::from(PRICE_PER_RECORD_SQUARED_WEI);
    let root = n_squared.root(2);
    // ruint's `Uint::to::<u64>()` panics on overflow. We MUST NOT panic here:
    // a hostile oversized price would otherwise be a pre-auth crash vector.
    // Saturate to `u64::MAX` instead; the delta check rejects out-of-range quotes.
    if root > Amount::from(u64::MAX) {
        u64::MAX
    } else {
        root.to::<u64>()
    }
}

/// Calculate storage price in wei from the number of close records stored.
///
/// Formula: `price_wei = BASELINE + n² × K / D²`
///
/// where `BASELINE = 0.00390625 ANT`, `K = 0.03515625 ANT`, and `D = 6000`.
/// U256 arithmetic prevents overflow for large record counts.
#[must_use]
pub fn calculate_price(close_records_stored: usize) -> Amount {
    let n = Amount::from(close_records_stored);
    let n_squared = n.saturating_mul(n);
    let quadratic_wei = n_squared.saturating_mul(Amount::from(PRICE_COEFFICIENT_WEI))
        / Amount::from(DIVISOR_SQUARED);
    Amount::from(PRICE_BASELINE_WEI).saturating_add(quadratic_wei)
}

// =============================================================================
// Pricing by record size: not used by any quote or payment path yet
// =============================================================================
//
// A record pays a fixed share φ of a full chunk's price, plus the rest of that
// price in proportion to the top of its size class:
//
//     w = φ + (1 − φ) × (class top ÷ FULL_RECORD_BYTES)
//
// with φ = 1/4 and nine size classes whose tops are the powers of two from
// 16 KiB to 4 MiB. A full chunk weighs exactly 1. A client pays
// `weighted_amount`, 3 × the median quote × w, and a node's fullness is its
// weight total, `weight_total`, in whole full chunks. A weight is an exact
// fraction over `WEIGHT_DENOMINATOR`, so every node and client computes the
// same amounts.

/// The size a record's weight is measured against: a full chunk, the largest
/// record and the top of the largest size class.
pub const FULL_RECORD_BYTES: u64 = 4 * 1024 * 1024;

/// The top of the smallest size class, which every record of this size or
/// smaller is in.
pub const SMALLEST_CLASS_BYTES: u64 = 16 * 1024;

/// φ, the share of a full chunk's price every record pays whatever its size,
/// is `FIXED_SHARE_NUMERATOR / FIXED_SHARE_DENOMINATOR`.
pub const FIXED_SHARE_NUMERATOR: u64 = 1;

/// See [`FIXED_SHARE_NUMERATOR`].
pub const FIXED_SHARE_DENOMINATOR: u64 = 4;

/// A record weight is a whole number of `1 / WEIGHT_DENOMINATOR` parts of a
/// full chunk.
pub const WEIGHT_DENOMINATOR: u64 = FIXED_SHARE_DENOMINATOR * FULL_RECORD_BYTES;

/// The share of a full chunk's price one record pays: [`Self::numerator`]
/// over [`WEIGHT_DENOMINATOR`], held exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordWeight(u64);

impl RecordWeight {
    /// A full chunk's weight: exactly 1.
    pub const FULL: Self = Self(WEIGHT_DENOMINATOR);

    /// The weight's numerator over [`WEIGHT_DENOMINATOR`].
    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.0
    }
}

/// The top of the size class a record of `len` bytes is in:
/// [`SMALLEST_CLASS_BYTES`] for `len` up to it, then the smallest power of
/// two at or above `len`, and [`FULL_RECORD_BYTES`] for `len` at or above
/// that.
#[must_use]
pub const fn size_class_top(len: u64) -> u64 {
    if len <= SMALLEST_CLASS_BYTES {
        SMALLEST_CLASS_BYTES
    } else if len >= FULL_RECORD_BYTES {
        FULL_RECORD_BYTES
    } else {
        len.next_power_of_two()
    }
}

/// The weight of a record of `data_type` that holds `len` bytes.
///
/// A chunk ([`DATA_TYPE_CHUNK`](crate::chunk::DATA_TYPE_CHUNK)) weighs by the
/// top of its size class. A pointer
/// ([`DATA_TYPE_POINTER`](crate::pointer::DATA_TYPE_POINTER)) weighs as a
/// record of [`POINTER_WIRE_LEN`](crate::pointer::POINTER_WIRE_LEN) bytes,
/// whatever `len` says, since every pointer is that size. A data type this
/// function doesn't know weighs as a full chunk.
#[must_use]
pub fn record_weight(data_type: u32, len: usize) -> RecordWeight {
    use crate::chunk::DATA_TYPE_CHUNK;
    use crate::pointer::{DATA_TYPE_POINTER, POINTER_WIRE_LEN};

    let size = match data_type {
        DATA_TYPE_CHUNK => u64::try_from(len).unwrap_or(u64::MAX),
        DATA_TYPE_POINTER => POINTER_WIRE_LEN as u64,
        _ => FULL_RECORD_BYTES,
    };
    RecordWeight(
        FIXED_SHARE_NUMERATOR * FULL_RECORD_BYTES
            + (FIXED_SHARE_DENOMINATOR - FIXED_SHARE_NUMERATOR) * size_class_top(size),
    )
}

/// What a client pays for a record of `weight` whose median quote is
/// `median_price`: 3 × `median_price` × `weight`, rounded up to the next wei,
/// so it is never below the exact amount. A full chunk pays exactly
/// 3 × `median_price`, the amount every payment carries today.
///
/// `None` if the amount overflows.
#[must_use]
pub fn weighted_amount(median_price: Amount, weight: RecordWeight) -> Option<Amount> {
    let scaled = median_price
        .checked_mul(Amount::from(3u64))?
        .checked_mul(Amount::from(weight.numerator()))?;
    Some(scaled.div_ceil(Amount::from(WEIGHT_DENOMINATOR)))
}

/// A node's weight total `m`, in whole full chunks: the weights of its
/// committed records, added up exactly and rounded up.
///
/// `m` is at least 1 when there is at least one record, never more than the
/// number of records, and equal to it when every record is a full chunk. A
/// record whose length isn't known is to be given as [`RecordWeight::FULL`].
#[must_use]
pub fn weight_total<I: IntoIterator<Item = RecordWeight>>(weights: I) -> u64 {
    let sum = weights.into_iter().fold(0u128, |sum, weight| {
        sum.saturating_add(u128::from(weight.numerator()))
    });
    u64::try_from(sum.div_ceil(u128::from(WEIGHT_DENOMINATOR))).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 1 token = 10¹⁸ wei (used for test sanity-checks).
    const WEI_PER_TOKEN: u128 = 1_000_000_000_000_000_000;

    /// Helper: expected price matching the formula `BASELINE + n² × K / D²`.
    fn expected_price(n: u64) -> Amount {
        let n_amt = Amount::from(n);
        let quad =
            n_amt * n_amt * Amount::from(PRICE_COEFFICIENT_WEI) / Amount::from(DIVISOR_SQUARED);
        Amount::from(PRICE_BASELINE_WEI) + quad
    }

    #[test]
    fn test_zero_records_gets_baseline() {
        let price = calculate_price(0);
        assert_eq!(price, Amount::from(PRICE_BASELINE_WEI));
    }

    #[test]
    fn test_baseline_is_nonzero_spam_barrier() {
        assert!(calculate_price(0) > Amount::ZERO);
        assert!(calculate_price(1) > calculate_price(0));
    }

    #[test]
    fn test_one_record_above_baseline() {
        let price = calculate_price(1);
        assert_eq!(price, expected_price(1));
        assert!(price > Amount::from(PRICE_BASELINE_WEI));
    }

    #[test]
    fn test_at_divisor_is_baseline_plus_k() {
        let price = calculate_price(6000);
        let expected = Amount::from(PRICE_BASELINE_WEI + PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_double_divisor_is_baseline_plus_four_k() {
        let price = calculate_price(12000);
        let expected = Amount::from(PRICE_BASELINE_WEI + 4 * PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_triple_divisor_is_baseline_plus_nine_k() {
        let price = calculate_price(18000);
        let expected = Amount::from(PRICE_BASELINE_WEI + 9 * PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_smooth_pricing_no_staircase() {
        let price_6k = calculate_price(6000);
        let price_11k = calculate_price(11999);
        assert!(
            price_11k > price_6k,
            "11999 records ({price_11k}) should cost more than 6000 ({price_6k})"
        );
    }

    #[test]
    fn test_price_increases_with_records() {
        let price_low = calculate_price(6000);
        let price_mid = calculate_price(12000);
        let price_high = calculate_price(18000);
        assert!(price_mid > price_low);
        assert!(price_high > price_mid);
    }

    #[test]
    fn test_price_increases_monotonically() {
        let mut prev_price = Amount::ZERO;
        for records in (0..60000).step_by(100) {
            let price = calculate_price(records);
            assert!(
                price >= prev_price,
                "Price at {records} records ({price}) should be >= previous ({prev_price})"
            );
            prev_price = price;
        }
    }

    #[test]
    fn test_large_value_no_overflow() {
        let price = calculate_price(usize::MAX);
        assert!(price > Amount::ZERO);
    }

    #[test]
    fn test_price_deterministic() {
        let price1 = calculate_price(12000);
        let price2 = calculate_price(12000);
        assert_eq!(price1, price2);
    }

    #[test]
    fn test_quadratic_growth_excluding_baseline() {
        let base = Amount::from(PRICE_BASELINE_WEI);
        let quad_6k = calculate_price(6000) - base;
        let quad_12k = calculate_price(12000) - base;
        let quad_24k = calculate_price(24000) - base;
        assert_eq!(quad_12k, quad_6k * Amount::from(4u64));
        assert_eq!(quad_24k, quad_6k * Amount::from(16u64));
    }

    #[test]
    fn test_small_record_counts_near_baseline() {
        let price = calculate_price(100);
        assert_eq!(price, expected_price(100));
        assert!(price < Amount::from(WEI_PER_TOKEN));
        assert!(price > Amount::from(PRICE_BASELINE_WEI));
    }

    #[test]
    fn test_derive_records_stored_from_price_round_trips() {
        for records in [0usize, 1, 5, 100, 6_000, 12_000, 60_000] {
            let price = calculate_price(records);
            assert_eq!(derive_records_stored_from_price(price), records as u64);
        }
    }

    #[test]
    fn test_derive_records_stored_from_baseline_or_lower_is_zero() {
        assert_eq!(derive_records_stored_from_price(Amount::ZERO), 0);
        assert_eq!(
            derive_records_stored_from_price(Amount::from(PRICE_BASELINE_WEI)),
            0
        );
    }

    #[test]
    fn test_derive_records_stored_from_max_price_saturates_no_panic() {
        let v = derive_records_stored_from_price(Amount::MAX);
        assert_eq!(v, u64::MAX);
    }
}
