//! Quadratic pricing with a baseline floor.
//!
//! Formula: `price_per_chunk(n) = BASELINE + K × (n / D)²`
//!
//! The non-zero `BASELINE` makes empty nodes charge a meaningful spam-barrier
//! price, and the quadratic term raises the price as a node fills.
//!
//! This is the **single source of truth** both the node (when pricing a quote)
//! and the client (when verifying ADR-0004's forced price before paying) must
//! agree on. It lives here, in the shared wire/contract crate, so the two sides
//! can never drift: `ant-node` re-exports [`calculate_price`] from this module
//! rather than defining its own.
//!
//! ## Parameters
//!
//! The current curve (Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor
//! 2,000):
//!
//! | Constant  | Value                | Role                                       |
//! |-----------|----------------------|--------------------------------------------|
//! | BASELINE  | 0.1396736 DARWIN     | Price at empty (spam barrier)              |
//! | K         | 1.2570624 DARWIN     | Quadratic coefficient, 9 × BASELINE        |
//! | D         | 2,000                | Records stored at which the price is 10 ×  |
//!
//! Derivation: 100 DARWIN per 10⁹ bytes × 4,190,208 bytes per full chunk ÷ 3
//! (a chunk pays 3 × the median quote) = 0.1396736 DARWIN per quote at an
//! empty node. K stays 9 × BASELINE as upstream, and with D = 2,000 the price
//! reaches 10 × (1,000 DARWIN per GB) at 2,000 records instead of 6,000. A GB
//! of full chunks costs exactly 100 DARWIN on empty nodes, 1,000 at 2,000
//! records and 8,200 at 6,000.
//!
//! | Legacy    | Value                | Role                                       |
//! |-----------|----------------------|--------------------------------------------|
//! | BASELINE  | 0.125 DARWIN         | Upstream's 0.00390625 × 32                 |
//! | K         | 1.125 DARWIN         | Upstream's 0.03515625 × 32                 |
//! | D         | 6,000                | Upstream's divisor                         |
//!
//! The legacy curve, upstream's constants × 32 (`LEGACY_PRICE_MULTIPLIER`), is
//! still accepted ([`calculate_price_legacy`], [`price_in_band_legacy`],
//! [`price_in_accepted_band`]); nodes no longer quote it from the node's price
//! switch time (`PRICE_SWITCH_AT`).

use evmlib::common::Amount;

/// Divisor `D` of the current curve, in records stored: the price is
/// 10 × BASELINE at `D` records (Dan, 2026-10-28 decision: 100 DARWIN per GB,
/// divisor 2,000).
const PRICING_DIVISOR: u128 = 2_000;

/// `PRICING_DIVISOR²`, precomputed to avoid repeated multiplication.
const DIVISOR_SQUARED: u128 = PRICING_DIVISOR * PRICING_DIVISOR;

/// Baseline price of the current curve, at an empty node.
///
/// 100 DARWIN per 10⁹ bytes × 4,190,208 bytes per full chunk ÷ 3 (a chunk
/// pays 3 × the median quote) = 0.1396736 DARWIN = `139_673_600_000_000_000`
/// wei (Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000).
/// Changing it means rebuilding nodes and clients together.
const PRICE_BASELINE_WEI: u128 = 139_673_600_000_000_000;

/// Quadratic coefficient `K` of the current curve: 9 × BASELINE, as upstream,
/// `1_257_062_400_000_000_000` wei (1.2570624 DARWIN).
const PRICE_COEFFICIENT_WEI: u128 = 9 * PRICE_BASELINE_WEI;

/// The legacy curve's scale on Autonomi's constants. Our network pays in
/// DARWIN instead of ANT, and this curve costs what Autonomi does in dollars
/// when DARWIN's market cap is $1M (1B supply, so $0.001 per DARWIN): the
/// factor is ANT's dollar price × 1,000. Set 2026-10-06 with ANT at $0.0319
/// (it was 7,381 for the Pons test token). Since Dan's 2026-10-28 decision
/// (100 DARWIN per GB, divisor 2,000) this curve is still accepted beside the
/// current one, and no longer quoted from the node's price switch time.
const LEGACY_PRICE_MULTIPLIER: u128 = 32;

/// Divisor `D` of the legacy curve, upstream's 6,000 records.
const LEGACY_PRICING_DIVISOR: u128 = 6_000;

/// `LEGACY_PRICING_DIVISOR²`.
const LEGACY_DIVISOR_SQUARED: u128 = LEGACY_PRICING_DIVISOR * LEGACY_PRICING_DIVISOR;

/// Baseline of the legacy curve: upstream's 0.00390625 ANT
/// (`3_906_250_000_000_000` wei) × 32.
const LEGACY_PRICE_BASELINE_WEI: u128 = 3_906_250_000_000_000 * LEGACY_PRICE_MULTIPLIER;

/// Quadratic coefficient of the legacy curve: upstream's 0.03515625 ANT
/// (`35_156_250_000_000_000` wei) × 32.
const LEGACY_PRICE_COEFFICIENT_WEI: u128 = 35_156_250_000_000_000 * LEGACY_PRICE_MULTIPLIER;

/// Price increment per squared record after simplifying `PRICE_COEFFICIENT_WEI / DIVISOR_SQUARED`:
/// `314_265_600_000` wei, an exact division.
const PRICE_PER_RECORD_SQUARED_WEI: u128 = PRICE_COEFFICIENT_WEI / DIVISOR_SQUARED;

/// Derive the quoted record count from a quote price.
///
/// This is the inverse of [`calculate_price`], the current curve (D = 2,000).
/// It intentionally floors to the nearest integer record count. The legacy
/// curve has no inverse: nothing in production inverts a price.
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

/// Calculate storage price in wei from the number of close records stored, on
/// the current curve.
///
/// Formula: `price_wei = BASELINE + n² × K / D²`
///
/// where `BASELINE = 0.1396736 DARWIN`, `K = 9 × BASELINE`, and `D = 2,000`
/// (Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000).
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

/// Calculate storage price in wei on the legacy curve, upstream's × 32:
/// `BASELINE = 0.125 DARWIN`, `K = 1.125 DARWIN`, `D = 6,000`. Still accepted
/// beside [`calculate_price`]; no longer quoted from the price switch.
#[must_use]
pub fn calculate_price_legacy(close_records_stored: usize) -> Amount {
    quadratic_price(
        close_records_stored,
        LEGACY_PRICE_BASELINE_WEI,
        LEGACY_PRICE_COEFFICIENT_WEI,
        LEGACY_DIVISOR_SQUARED,
    )
}

/// `baseline + n² × coefficient / divisor_squared`, saturating, in wei.
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

/// Whether `price` is in [`price_band`]`(key_count)`, the current curve's band.
#[must_use]
pub fn price_in_band(price: &Amount, key_count: u64) -> bool {
    let (bottom, top) = price_band(key_count);
    bottom <= *price && *price <= top
}

/// [`price_band`] on the legacy curve: the same two ends, computed through
/// [`calculate_price_legacy`].
#[must_use]
pub fn price_band_legacy(key_count: u64) -> (Amount, Amount) {
    let to_usize = |count: u64| usize::try_from(count).unwrap_or(usize::MAX);
    (
        calculate_price_legacy(to_usize(band_bottom_count(key_count))),
        calculate_price_legacy(to_usize(key_count)),
    )
}

/// Whether `price` is in [`price_band_legacy`]`(key_count)`.
#[must_use]
pub fn price_in_band_legacy(price: &Amount, key_count: u64) -> bool {
    let (bottom, top) = price_band_legacy(key_count);
    bottom <= *price && *price <= top
}

/// The band check every quote check uses: `price` is valid for `key_count`
/// on either curve, each band checked exactly as before (Dan, 2026-10-28
/// decision: 100 DARWIN per GB, divisor 2,000, with the legacy curve still
/// accepted).
#[must_use]
pub fn price_in_accepted_band(price: &Amount, key_count: u64) -> bool {
    price_in_band(price, key_count) || price_in_band_legacy(price, key_count)
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
        let price = calculate_price(usize::try_from(PRICING_DIVISOR).unwrap());
        let expected = Amount::from(PRICE_BASELINE_WEI + PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_double_divisor_is_baseline_plus_four_k() {
        let price = calculate_price(usize::try_from(2 * PRICING_DIVISOR).unwrap());
        let expected = Amount::from(PRICE_BASELINE_WEI + 4 * PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_triple_divisor_is_baseline_plus_nine_k() {
        let price = calculate_price(usize::try_from(3 * PRICING_DIVISOR).unwrap());
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

    #[test]
    fn current_curve_constants() {
        // Dan, 2026-10-28 decision: 100 DARWIN per GB, divisor 2,000.
        assert_eq!(calculate_price(0), Amount::from(139_673_600_000_000_000u128));
        assert_eq!(PRICE_COEFFICIENT_WEI, 9 * PRICE_BASELINE_WEI);
        assert_eq!(PRICE_COEFFICIENT_WEI, 1_257_062_400_000_000_000);
        assert_eq!(
            PRICE_PER_RECORD_SQUARED_WEI * DIVISOR_SQUARED,
            PRICE_COEFFICIENT_WEI
        );
    }

    #[test]
    fn legacy_curve_is_upstream_times_32() {
        assert_eq!(
            calculate_price_legacy(0),
            Amount::from(125_000_000_000_000_000u128)
        );
        assert_eq!(
            calculate_price_legacy(6_000),
            Amount::from(1_250_000_000_000_000_000u128)
        );
    }

    #[test]
    fn legacy_curve_is_never_above_the_current_curve() {
        for n in (0..60_000).step_by(100) {
            assert!(calculate_price_legacy(n) <= calculate_price(n), "n = {n}");
        }
    }

    #[test]
    fn accepted_band_is_either_curves_band() {
        let k = 500u64;
        assert_eq!(band_bottom_count(k), 126);
        let (bottom, top) = price_band(k);
        let (legacy_bottom, legacy_top) = price_band_legacy(k);
        for price in [bottom, top, legacy_bottom, legacy_top] {
            assert!(price_in_accepted_band(&price, k), "{price}");
        }
        assert!(!price_in_accepted_band(
            &(calculate_price_legacy(500) + Amount::from(1u64)),
            k
        ));
        assert!(!price_in_accepted_band(
            &(calculate_price(126) - Amount::from(1u64)),
            k
        ));
    }
}
