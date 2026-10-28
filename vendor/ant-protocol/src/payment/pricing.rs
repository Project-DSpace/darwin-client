//! Quadratic pricing with a baseline floor.
//!
//! Formula: `price_per_quote(n) = BASELINE + K × (n / D)²`, in wei of DARWIN,
//! with `n` the records a node stores.
//!
//! The non-zero `BASELINE` makes empty nodes charge a meaningful spam-barrier
//! price, and the quadratic term raises the price as nodes fill.
//!
//! This is the **single source of truth** both the node (when pricing a quote)
//! and the client (when verifying ADR-0004's forced price before paying) must
//! agree on. It lives here, in the shared wire/contract crate, so the two sides
//! can never drift: `ant-node` re-exports [`calculate_price`] from this module
//! rather than defining its own.
//!
//! ## Parameters
//!
//! The current curve, [`calculate_price`] (Dan, 2026-10-28 decision: 100 DARWIN
//! per GB, divisor 2,000):
//!
//! | Constant  | Value            | Role                                              |
//! |-----------|------------------|---------------------------------------------------|
//! | BASELINE  | 0.1396736 DARWIN | Price at empty: 100 DARWIN per GB of full chunks  |
//! | K         | 1.2570624 DARWIN | Quadratic coefficient, 9 × BASELINE               |
//! | D         | 2000             | Records at which the price is 10 × BASELINE       |
//!
//! The legacy curve, [`calculate_price_legacy`], is the curve to ds.19:
//! upstream's constants × 32 (BASELINE 0.125 DARWIN, K 1.125 DARWIN, D 6000).
//! Nodes quote it until their switch time and the current curve from then on;
//! a quote priced on either curve is accepted ([`price_in_band`]).

use evmlib::common::Amount;

/// Records stored at which the current curve reaches 10 × its baseline
/// (Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000).
const PRICING_DIVISOR: u128 = 2_000;

/// `PRICING_DIVISOR²`, precomputed to avoid repeated multiplication.
const DIVISOR_SQUARED: u128 = PRICING_DIVISOR * PRICING_DIVISOR;

/// Baseline price of a quote at an empty node, in wei of DARWIN.
///
/// 100 DARWIN per 10⁹ bytes × 4,190,208 bytes per full chunk ÷ 3 (a chunk
/// pays 3 × the median quote) = 0.1396736 DARWIN per quote at an empty node
/// (Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000). A GB of full
/// chunks costs exactly 100 DARWIN on empty nodes, 1,000 at 2,000 records and
/// 8,200 at 6,000. Changing it means rebuilding nodes and clients together.
const PRICE_BASELINE_WEI: u128 = 139_673_600_000_000_000;

/// Quadratic coefficient `K`: 9 × the baseline, as upstream, so the price is
/// 10 × the baseline (1,000 DARWIN per GB) at [`PRICING_DIVISOR`] records
/// instead of at 6,000. `1.2570624 DARWIN = 1_257_062_400_000_000_000 wei`.
const PRICE_COEFFICIENT_WEI: u128 = 9 * PRICE_BASELINE_WEI;

/// Price increment per squared record after simplifying
/// `PRICE_COEFFICIENT_WEI / DIVISOR_SQUARED` (exactly 314_265_600_000).
const PRICE_PER_RECORD_SQUARED_WEI: u128 = PRICE_COEFFICIENT_WEI / DIVISOR_SQUARED;

/// The legacy curve's factor over upstream's constants. The legacy curve is
/// the curve to ds.19, accepted beside the current curve. The factor was set
/// 2026-10-06 so that DARWIN at a $1M market cap cost what Autonomi does in
/// dollars, with ANT at $0.0319.
const LEGACY_PRICE_MULTIPLIER: u128 = 32;

/// The legacy curve's divisor, upstream's.
const LEGACY_PRICING_DIVISOR: u128 = 6_000;

/// `LEGACY_PRICING_DIVISOR²`.
const LEGACY_DIVISOR_SQUARED: u128 = LEGACY_PRICING_DIVISOR * LEGACY_PRICING_DIVISOR;

/// The legacy baseline: upstream's `0.00390625 ANT` × 32 = 0.125 DARWIN.
const LEGACY_PRICE_BASELINE_WEI: u128 = 3_906_250_000_000_000 * LEGACY_PRICE_MULTIPLIER;

/// The legacy coefficient: upstream's `0.03515625 ANT` × 32 = 1.125 DARWIN.
const LEGACY_PRICE_COEFFICIENT_WEI: u128 = 35_156_250_000_000_000 * LEGACY_PRICE_MULTIPLIER;

/// `LEGACY_PRICE_COEFFICIENT_WEI / LEGACY_DIVISOR_SQUARED` (exactly 31_250_000_000).
const LEGACY_PRICE_PER_RECORD_SQUARED_WEI: u128 =
    LEGACY_PRICE_COEFFICIENT_WEI / LEGACY_DIVISOR_SQUARED;

/// `baseline + n² × coefficient / divisor_squared`, in U256 with saturating
/// arithmetic, so no record count overflows.
fn quadratic_price(
    close_records_stored: usize,
    baseline: u128,
    coefficient: u128,
    divisor_squared: u128,
) -> Amount {
    let n = Amount::from(close_records_stored);
    let n_squared = n.saturating_mul(n);
    let quadratic_wei =
        n_squared.saturating_mul(Amount::from(coefficient)) / Amount::from(divisor_squared);
    Amount::from(baseline).saturating_add(quadratic_wei)
}

/// The record count the curve of `baseline` and `per_record_squared` prices at
/// `price`, floored, and saturated to `u64::MAX`.
fn derive_records(price: Amount, baseline: u128, per_record_squared: u128) -> u64 {
    let baseline = Amount::from(baseline);
    if price <= baseline {
        return 0;
    }

    let excess = price - baseline;
    let n_squared = excess / Amount::from(per_record_squared);
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

/// Derive the quoted record count from a quote price on the current curve.
///
/// This is the inverse of [`calculate_price`] (divisor 2,000). It
/// intentionally floors to the nearest integer record count.
///
/// Saturates to `u64::MAX` for any price that would otherwise overflow `u64`.
/// This matters because the node verifier calls this on untrusted deserialized
/// `quote.price` values BEFORE signature verification: a panic here is a
/// pre-auth crash vector. Saturating leaves the delta check to reject the
/// quote as out-of-range without aborting the process.
#[must_use]
pub fn derive_records_stored_from_price(price: Amount) -> u64 {
    derive_records(price, PRICE_BASELINE_WEI, PRICE_PER_RECORD_SQUARED_WEI)
}

/// Derive the quoted record count from a quote price on the legacy curve:
/// the inverse of [`calculate_price_legacy`] (divisor 6,000), floored and
/// saturating like [`derive_records_stored_from_price`].
#[must_use]
pub fn derive_records_stored_from_price_legacy(price: Amount) -> u64 {
    derive_records(
        price,
        LEGACY_PRICE_BASELINE_WEI,
        LEGACY_PRICE_PER_RECORD_SQUARED_WEI,
    )
}

/// Calculate storage price in wei from the number of close records stored,
/// on the current curve.
///
/// Formula: `price_wei = BASELINE + n² × K / D²`
///
/// where `BASELINE = 0.1396736 DARWIN`, `K = 9 × BASELINE = 1.2570624 DARWIN`,
/// and `D = 2000` (Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000).
/// U256 arithmetic prevents overflow for large record counts.
#[must_use]
pub fn calculate_price(close_records_stored: usize) -> Amount {
    quadratic_price(
        close_records_stored,
        PRICE_BASELINE_WEI,
        PRICE_COEFFICIENT_WEI,
        DIVISOR_SQUARED,
    )
}

/// Calculate storage price in wei from the number of close records stored,
/// on the legacy curve: the curve to ds.19, upstream's constants × 32.
///
/// Formula: `price_wei = BASELINE + n² × K / D²`
///
/// where `BASELINE = 0.125 DARWIN`, `K = 1.125 DARWIN`, and `D = 6000`.
/// Nodes quote it until their switch time; quotes on it stay accepted.
#[must_use]
pub fn calculate_price_legacy(close_records_stored: usize) -> Amount {
    quadratic_price(
        close_records_stored,
        LEGACY_PRICE_BASELINE_WEI,
        LEGACY_PRICE_COEFFICIENT_WEI,
        LEGACY_DIVISOR_SQUARED,
    )
}

// =============================================================================
// Pricing by record size
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

/// The smallest weight total a node committing to `key_count` records can
/// have: every record in the smallest size class, `floor(w_min × key_count)`,
/// with `w_min` the smallest class's weight (259/1,024 at φ = 1/4).
///
/// An honest node's weight total is always at or above it, since its exact
/// weight sum is at least `w_min × key_count` and it rounds up.
#[must_use]
pub fn band_bottom_count(key_count: u64) -> u64 {
    let smallest = record_weight(crate::chunk::DATA_TYPE_CHUNK, 0).numerator();
    let bottom = u128::from(key_count) * u128::from(smallest) / u128::from(WEIGHT_DENOMINATOR);
    u64::try_from(bottom).unwrap_or(u64::MAX)
}

/// The prices a quote committing to `key_count` records may carry on the
/// current curve, both ends included: from
/// `calculate_price(band_bottom_count(key_count))`, every record in the
/// smallest class, to `calculate_price(key_count)`, every record a full chunk.
///
/// Both ends are computed forward through [`calculate_price`]; the price is
/// never inverted to a count. With no records the band is the one price
/// `calculate_price(0)`.
#[must_use]
pub fn price_band(key_count: u64) -> (Amount, Amount) {
    let to_usize = |count: u64| usize::try_from(count).unwrap_or(usize::MAX);
    (
        calculate_price(to_usize(band_bottom_count(key_count))),
        calculate_price(to_usize(key_count)),
    )
}

/// The same band as [`price_band`] on the legacy curve: from
/// `calculate_price_legacy(band_bottom_count(key_count))` to
/// `calculate_price_legacy(key_count)`, both computed forward.
#[must_use]
pub fn price_band_legacy(key_count: u64) -> (Amount, Amount) {
    let to_usize = |count: u64| usize::try_from(count).unwrap_or(usize::MAX);
    (
        calculate_price_legacy(to_usize(band_bottom_count(key_count))),
        calculate_price_legacy(to_usize(key_count)),
    )
}

/// Whether `price` is in [`price_band`]`(key_count)` or in
/// [`price_band_legacy`]`(key_count)`.
///
/// Both curves are accepted because nodes switch from the legacy curve to the
/// current one at a fixed time, and ds.19 nodes quote the legacy curve, so a
/// network of mixed releases quotes on both. Each band is checked whole, with
/// the same rules.
#[must_use]
pub fn price_in_band(price: &Amount, key_count: u64) -> bool {
    let in_band = |(bottom, top): (Amount, Amount)| bottom <= *price && *price <= top;
    in_band(price_band(key_count)) || in_band(price_band_legacy(key_count))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // The divisor-relative tests below run on the current curve's divisor,
    // 2,000 records (Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000).

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
        let price = calculate_price(2000);
        let expected = Amount::from(PRICE_BASELINE_WEI + PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_double_divisor_is_baseline_plus_four_k() {
        let price = calculate_price(4000);
        let expected = Amount::from(PRICE_BASELINE_WEI + 4 * PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_triple_divisor_is_baseline_plus_nine_k() {
        let price = calculate_price(6000);
        let expected = Amount::from(PRICE_BASELINE_WEI + 9 * PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_smooth_pricing_no_staircase() {
        let price_2k = calculate_price(2000);
        let price_4k = calculate_price(3999);
        assert!(
            price_4k > price_2k,
            "3999 records ({price_4k}) should cost more than 2000 ({price_2k})"
        );
    }

    #[test]
    fn test_price_increases_with_records() {
        let price_low = calculate_price(2000);
        let price_mid = calculate_price(4000);
        let price_high = calculate_price(6000);
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
        assert!(calculate_price_legacy(usize::MAX) > Amount::ZERO);
    }

    #[test]
    fn test_price_deterministic() {
        let price1 = calculate_price(4000);
        let price2 = calculate_price(4000);
        assert_eq!(price1, price2);
    }

    #[test]
    fn test_quadratic_growth_excluding_baseline() {
        let base = Amount::from(PRICE_BASELINE_WEI);
        let quad_2k = calculate_price(2000) - base;
        let quad_4k = calculate_price(4000) - base;
        let quad_8k = calculate_price(8000) - base;
        assert_eq!(quad_4k, quad_2k * Amount::from(4u64));
        assert_eq!(quad_8k, quad_2k * Amount::from(16u64));
    }

    #[test]
    fn test_small_record_counts_near_baseline() {
        let price = calculate_price(100);
        assert_eq!(price, expected_price(100));
        assert!(price < Amount::from(WEI_PER_TOKEN));
        assert!(price > Amount::from(PRICE_BASELINE_WEI));
    }

    /// Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000. A full
    /// chunk (4,190,208 bytes) pays 3 × the median quote, so on empty nodes
    /// 10⁹ bytes of full chunks cost exactly 100 DARWIN.
    #[test]
    fn test_100_darwin_per_gb_on_empty_nodes() {
        assert_eq!(
            calculate_price(0),
            Amount::from(139_673_600_000_000_000u128)
        );
        assert_eq!(
            Amount::from(3u64) * calculate_price(0) * Amount::from(1_000_000_000u64),
            Amount::from(100 * WEI_PER_TOKEN) * Amount::from(4_190_208u64)
        );
        assert_eq!(PRICE_COEFFICIENT_WEI, 1_257_062_400_000_000_000);
        assert_eq!(PRICE_PER_RECORD_SQUARED_WEI, 314_265_600_000);
        assert_eq!(
            PRICE_PER_RECORD_SQUARED_WEI * DIVISOR_SQUARED,
            PRICE_COEFFICIENT_WEI
        );
    }

    /// Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000. The price
    /// is 10 × the empty price (1,000 DARWIN per GB) at 2,000 records and
    /// 82 × (8,200 DARWIN per GB) at 6,000.
    #[test]
    fn test_ten_times_at_2000_records() {
        assert_eq!(
            calculate_price(2000),
            calculate_price(0) * Amount::from(10u64)
        );
        assert_eq!(
            calculate_price(6000),
            calculate_price(0) * Amount::from(82u64)
        );
    }

    /// The legacy curve, accepted beside the current one, is upstream's
    /// constants × 32 with divisor 6,000: the curve to ds.19.
    #[test]
    fn test_legacy_curve_is_upstream_times_32() {
        assert_eq!(
            calculate_price_legacy(0),
            Amount::from(125_000_000_000_000_000u128)
        );
        assert_eq!(
            calculate_price_legacy(6000),
            Amount::from(1_250_000_000_000_000_000u128)
        );
        assert_eq!(LEGACY_PRICE_PER_RECORD_SQUARED_WEI, 31_250_000_000);
        assert_eq!(
            LEGACY_PRICE_PER_RECORD_SQUARED_WEI * LEGACY_DIVISOR_SQUARED,
            LEGACY_PRICE_COEFFICIENT_WEI
        );
    }

    #[test]
    fn test_derive_records_stored_from_price_round_trips() {
        for records in [0usize, 1, 5, 100, 2_000, 4_000, 6_000, 12_000, 60_000] {
            let price = calculate_price(records);
            assert_eq!(derive_records_stored_from_price(price), records as u64);
            let legacy = calculate_price_legacy(records);
            assert_eq!(
                derive_records_stored_from_price_legacy(legacy),
                records as u64
            );
        }
    }

    #[test]
    fn test_derive_records_stored_from_baseline_or_lower_is_zero() {
        assert_eq!(derive_records_stored_from_price(Amount::ZERO), 0);
        assert_eq!(
            derive_records_stored_from_price(Amount::from(PRICE_BASELINE_WEI)),
            0
        );
        assert_eq!(derive_records_stored_from_price_legacy(Amount::ZERO), 0);
        assert_eq!(
            derive_records_stored_from_price_legacy(Amount::from(LEGACY_PRICE_BASELINE_WEI)),
            0
        );
    }

    #[test]
    fn test_derive_records_stored_from_max_price_saturates_no_panic() {
        let v = derive_records_stored_from_price(Amount::MAX);
        assert_eq!(v, u64::MAX);
        assert_eq!(
            derive_records_stored_from_price_legacy(Amount::MAX),
            u64::MAX
        );
    }

    /// Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000. A quote is
    /// accepted in either curve's band, each band checked whole.
    #[test]
    fn test_price_in_band_accepts_either_curve() {
        // At 1,024 keys the band bottom count is 259.
        assert_eq!(band_bottom_count(1024), 259);
        for price in [
            calculate_price(1024),
            calculate_price(259),
            calculate_price_legacy(1024),
            calculate_price_legacy(259),
        ] {
            assert!(price_in_band(&price, 1024), "{price}");
        }
        // Between the legacy top (157.768e15) and the current bottom
        // (about 160.75e15): on neither curve.
        assert!(!price_in_band(
            &Amount::from(159_000_000_000_000_000u128),
            1024
        ));
        assert!(!price_in_band(
            &(calculate_price_legacy(259) - Amount::from(1u64)),
            1024
        ));
        assert!(!price_in_band(
            &(calculate_price(1024) + Amount::from(1u64)),
            1024
        ));

        assert!(price_in_band(&calculate_price(0), 0));
        assert!(price_in_band(&calculate_price_legacy(0), 0));
        assert!(!price_in_band(
            &Amount::from(130_000_000_000_000_000u128),
            0
        ));
    }
}
