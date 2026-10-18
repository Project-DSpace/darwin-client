//! Native resolve-before-pay policy, independent of quote wire format.
//!
//! Adapters retain their protocol's amount and cryptographic types. The order
//! and meaning of the checks here come from the native client's quote gate.

use std::fmt::Display;

pub(crate) const ML_DSA_PUB_KEY_LEN: usize =
    ant_protocol::pqc::api::MlDsaVariant::MlDsa65.public_key_size();

pub(crate) trait QuotePrice: Copy + Eq + Display {
    fn for_key_count(count: u32) -> Self;
}

impl QuotePrice for ant_protocol::evm::Amount {
    fn for_key_count(count: u32) -> Self {
        ant_protocol::payment::calculate_price(count as usize)
    }
}

/// Protocol primitives supplied by each wire adapter; admission is shared.
pub(crate) trait Commitment: serde::de::DeserializeOwned {
    const MAX_KEY_COUNT: u32;
    const MAX_SIDECAR_BYTES: usize;
    fn peer(&self) -> &[u8; 32];
    fn public_key(&self) -> &[u8];
    fn key_count(&self) -> u32;
    fn verify_signature(&self) -> bool;
    fn hash(&self) -> Option<[u8; 32]>;
}

macro_rules! commitment_adapter {
    ($protocol:path) => {
        use $protocol as protocol;
        impl Commitment for protocol::StorageCommitment {
            const MAX_KEY_COUNT: u32 = protocol::MAX_COMMITMENT_KEY_COUNT;
            const MAX_SIDECAR_BYTES: usize = protocol::MAX_COMMITMENT_SIDECAR_BYTES;
            fn peer(&self) -> &[u8; 32] {
                &self.sender_peer_id
            }
            fn public_key(&self) -> &[u8] {
                &self.sender_public_key
            }
            fn key_count(&self) -> u32 {
                self.key_count
            }
            fn verify_signature(&self) -> bool {
                protocol::verify_commitment_signature(self)
            }
            fn hash(&self) -> Option<[u8; 32]> {
                protocol::commitment_hash(self)
            }
        }
    };
}

mod native {
    use super::Commitment;
    commitment_adapter!(ant_protocol::payment::commitment);
}

pub(crate) struct QuoteFields<'a, P> {
    pub(crate) public_key: &'a [u8],
    pub(crate) content: &'a [u8; 32],
    pub(crate) price: P,
    pub(crate) committed_key_count: u32,
    pub(crate) commitment_pin: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum QuoteValidationError {
    #[error("{0}")]
    Binding(String),
    #[error("{0}")]
    Commitment(String),
}

pub(crate) fn peer_binding_is_valid(peer: &[u8; 32], public_key: &[u8]) -> bool {
    public_key.len() == ML_DSA_PUB_KEY_LEN && blake3::hash(public_key).as_bytes() == peer
}

pub(crate) fn validate_quote<P: QuotePrice, C: Commitment>(
    peer: &[u8; 32],
    expected_content: &[u8; 32],
    fields: &QuoteFields<'_, P>,
    verify_signature: impl FnOnce() -> bool,
    sidecar: Option<&[u8]>,
) -> Result<(), QuoteValidationError> {
    if !peer_binding_is_valid(peer, fields.public_key) {
        return Err(QuoteValidationError::Binding(format!(
            "BLAKE3(pub_key)={} pub_key_len={}",
            blake3::hash(fields.public_key).to_hex(),
            fields.public_key.len(),
        )));
    }
    if fields.content != expected_content {
        return Err(QuoteValidationError::Binding(
            "quote content does not match the requested address".into(),
        ));
    }
    if !verify_signature() {
        return Err(QuoteValidationError::Binding(
            "quote ML-DSA-65 signature is invalid".into(),
        ));
    }
    validate_commitment_binding::<P, C>(peer, fields, sidecar)
        .map_err(QuoteValidationError::Commitment)
}

pub(crate) fn validate_commitment_binding<P: QuotePrice, C: Commitment>(
    peer: &[u8; 32],
    fields: &QuoteFields<'_, P>,
    sidecar: Option<&[u8]>,
) -> Result<(), String> {
    let count = fields.committed_key_count;
    let pin = fields.commitment_pin;
    match (count, pin.is_some()) {
        (0, false) | (1.., true) => {}
        (1.., false) => {
            return Err(format!(
                "committed_key_count={count} > 0 but commitment_pin is None (unauditable count)"
            ))
        }
        (0, true) => {
            return Err("committed_key_count=0 with a commitment_pin (incoherent baseline)".into())
        }
    }
    if count > C::MAX_KEY_COUNT {
        return Err(format!(
            "committed_key_count={count} exceeds MAX_COMMITMENT_KEY_COUNT={}",
            C::MAX_KEY_COUNT
        ));
    }
    let expected = P::for_key_count(count);
    if fields.price != expected {
        return Err(format!(
            "price {} does not equal calculate_price(committed_key_count={count}) = {expected}",
            fields.price
        ));
    }
    // Native baseline semantics: there is no pin to resolve. Any unsolicited
    // sidecar is irrelevant to admission, including an unparseable one.
    let Some(pin) = pin else {
        return Ok(());
    };
    let Some(blob) = sidecar else {
        return Err("bound quote did not ship its commitment; the pin is unresolvable so the quote is dropped before payment".into());
    };
    if blob.len() > C::MAX_SIDECAR_BYTES {
        return Err(format!(
            "shipped commitment is {} bytes, exceeds MAX_COMMITMENT_SIDECAR_BYTES={}",
            blob.len(),
            C::MAX_SIDECAR_BYTES
        ));
    }
    let commitment: C = rmp_serde::from_slice(blob).map_err(|e| {
        format!("shipped commitment did not deserialize as a StorageCommitment: {e}")
    })?;
    if blake3::hash(commitment.public_key()).as_bytes() != peer || commitment.peer() != peer {
        return Err("shipped commitment is not bound to the quoting peer".into());
    }
    if !commitment.verify_signature() {
        return Err("shipped commitment has an invalid signature".into());
    }
    if commitment.hash() != Some(pin) {
        return Err("shipped commitment does not hash to the quote's pin".into());
    }
    if commitment.key_count() != count {
        return Err(format!(
            "shipped commitment attests key_count={} but the quote claims {count}",
            commitment.key_count()
        ));
    }
    Ok(())
}

/// The caller's price ceiling: the most a quote may ask for one chunk
/// (`ClientConfig::max_chunk_price`), checked after the price is known to be
/// the one its commitment forces. A quote asking more is dropped before
/// payment, as if its node hadn't answered. `None`: no ceiling.
pub(crate) fn validate_price_ceiling<P: QuotePrice + Ord>(
    price: P,
    ceiling: Option<P>,
) -> Result<(), String> {
    match ceiling {
        Some(ceiling) if price > ceiling => Err(format!(
            "price {price} is above the price ceiling {ceiling}"
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_protocol::evm::Amount;

    #[test]
    fn a_price_ceiling_drops_only_quotes_above_it() {
        let price = Amount::from(1_000u64);
        assert!(validate_price_ceiling(price, None).is_ok(), "no ceiling");
        assert!(validate_price_ceiling(price, Some(price)).is_ok());
        assert!(validate_price_ceiling(price, Some(Amount::from(1_001u64))).is_ok());
        let error = validate_price_ceiling(price, Some(Amount::from(999u64))).unwrap_err();
        assert_eq!(error, "price 1000 is above the price ceiling 999");
    }

    /// Upstream's price for a node storing nothing, in wei (0.00390625 ANT).
    const UPSTREAM_BASELINE_WEI: u128 = 3_906_250_000_000_000;

    /// Upstream's quadratic coefficient, in wei (0.03515625 ANT): what the
    /// price adds to the baseline at the curve's divisor of 6,000 records.
    const UPSTREAM_COEFFICIENT_WEI: u128 = 35_156_250_000_000_000;

    /// This network's multiplier over upstream's prices, set in
    /// `vendor/ant-protocol/src/payment/pricing.rs`, which `[patch.crates-io]`
    /// puts in place of the crates.io release. Clients and nodes must carry
    /// the same multiplier, or the forced-price check drops the nodes' quotes.
    const PRICE_MULTIPLIER: u128 = 32;

    /// A quote priced as Autonomi's nodes price it, without this network's
    /// multiplier, fails the forced-price check, so nothing is paid to a node
    /// of Autonomi's network a client reaches. The same quote at 32 times the
    /// price passes.
    #[test]
    fn quotes_priced_at_upstreams_rate_are_rejected() {
        let public_key = vec![7u8; ML_DSA_PUB_KEY_LEN];
        let peer = *blake3::hash(&public_key).as_bytes();
        let content = [9u8; 32];
        let quote_at = |wei: u128| {
            let fields = QuoteFields {
                public_key: &public_key,
                content: &content,
                price: Amount::from(wei),
                committed_key_count: 0,
                commitment_pin: None,
            };
            validate_quote::<Amount, ant_protocol::payment::commitment::StorageCommitment>(
                &peer,
                &content,
                &fields,
                || true,
                None,
            )
        };
        let error = quote_at(UPSTREAM_BASELINE_WEI).unwrap_err().to_string();
        assert!(
            error.contains("does not equal calculate_price(committed_key_count=0)"),
            "{error}"
        );
        assert!(quote_at(UPSTREAM_BASELINE_WEI * PRICE_MULTIPLIER).is_ok());
    }

    #[test]
    fn forced_prices_carry_the_networks_multiplier() {
        let baseline = Amount::from(UPSTREAM_BASELINE_WEI * PRICE_MULTIPLIER);
        assert_eq!(ant_protocol::payment::calculate_price(0), baseline);
        // The price `validate_commitment_binding` holds a quote to.
        assert_eq!(Amount::for_key_count(0), baseline);
        assert_eq!(
            Amount::for_key_count(6_000),
            Amount::from((UPSTREAM_BASELINE_WEI + UPSTREAM_COEFFICIENT_WEI) * PRICE_MULTIPLIER)
        );
    }
}
