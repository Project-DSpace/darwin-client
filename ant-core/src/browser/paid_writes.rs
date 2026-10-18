//! Uploads and pointer writes from the browser core: off in this build.
//!
//! The browser's uploads store a plain data map, or staged records with no
//! envelope, so they have no payment record or listing; nothing reads a
//! paid quote back; and a page can ask for batch (merkle) payment. Until
//! they carry envelopes, the read-back of paid quotes and per-chunk-only
//! payment, every export that pays or stores refuses before it asks for a
//! quote, calls the page's wallet or sends anything: `uploadPublicFile`,
//! `uploadStagedPublicFile`, `uploadRecords`, `createPointer`,
//! `updatePointer`, `transferPointer` and `storePaidPointer`. Reads are
//! unchanged: downloads, `getPointer`, `resolvePointer` and
//! `pointerFinality`.

use crate::data::client::merkle::PaymentMode;

/// Whether the browser core uploads and writes pointers.
#[cfg_attr(
    not(all(target_arch = "wasm32", feature = "browser-wasm")),
    allow(dead_code)
)]
pub(super) const BROWSER_PAYMENTS: bool = false;

/// What a page is told when it asks for an upload or a pointer write.
#[cfg_attr(
    not(all(target_arch = "wasm32", feature = "browser-wasm")),
    allow(dead_code)
)]
pub(super) const BROWSER_PAYMENTS_OFF: &str = "uploads and pointer writes from the browser core \
     are off in this build: they don't yet carry the payment record, the read-back of paid \
     quotes, or per-chunk-only payment. Use the darwin client.";

/// Refuse an upload or a pointer write while [`BROWSER_PAYMENTS`] is off.
#[cfg_attr(
    not(all(target_arch = "wasm32", feature = "browser-wasm")),
    allow(dead_code)
)]
pub(super) fn check_browser_payments() -> Result<(), &'static str> {
    if BROWSER_PAYMENTS {
        Ok(())
    } else {
        Err(BROWSER_PAYMENTS_OFF)
    }
}

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

    /// Uploads and pointer writes stay off until they carry envelopes, the
    /// read-back of paid quotes and per-chunk-only payment: every paid
    /// export is refused with this message.
    #[test]
    fn browser_uploads_and_pointer_writes_are_off() {
        const { assert!(!BROWSER_PAYMENTS) };
        assert_eq!(check_browser_payments(), Err(BROWSER_PAYMENTS_OFF));
        for words in [
            "uploads and pointer writes from the browser core are off in this build",
            "the payment record",
            "the read-back of paid quotes",
            "per-chunk-only payment",
            "Use the darwin client.",
        ] {
            assert!(BROWSER_PAYMENTS_OFF.contains(words), "{words}");
        }
    }

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
