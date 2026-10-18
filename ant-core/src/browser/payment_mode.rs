//! The payment mode a browser upload names: its `paymentMode` argument.
//!
//! Compiled natively too, so the mapping is tested without a browser. A page
//! that names none pays per chunk, as [`PaymentMode`]'s default does.

use crate::data::client::merkle::PaymentMode;

/// The payment mode a browser upload names (its `paymentMode` argument):
/// per chunk unless it asks for another, as [`PaymentMode`]'s default is.
#[cfg_attr(
    not(all(target_arch = "wasm32", feature = "browser-wasm")),
    allow(dead_code)
)]
pub(super) fn payment_mode_named(name: Option<&str>) -> Result<PaymentMode, &'static str> {
    match name {
        None | Some("single") => Ok(PaymentMode::Single),
        Some("auto") => Ok(PaymentMode::Auto),
        Some("merkle") => Ok(PaymentMode::Merkle),
        Some(_) => Err("unknown payment mode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page that names no payment mode, or `single`, pays per chunk; the
    /// other names map as before, and anything else is refused.
    #[test]
    fn payment_modes_are_named_as_the_browser_names_them() {
        assert_eq!(payment_mode_named(None), Ok(PaymentMode::Single));
        assert_eq!(payment_mode_named(Some("single")), Ok(PaymentMode::Single));
        assert_eq!(payment_mode_named(Some("auto")), Ok(PaymentMode::Auto));
        assert_eq!(payment_mode_named(Some("merkle")), Ok(PaymentMode::Merkle));
        for unknown in ["", "Single", "batch", " single"] {
            assert_eq!(
                payment_mode_named(Some(unknown)),
                Err("unknown payment mode"),
                "{unknown:?}"
            );
        }
    }
}
