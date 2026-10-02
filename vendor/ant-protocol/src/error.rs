//! Error and `Result` types for `ant-protocol`.
//!
//! Kept intentionally small: this crate is a wire contract, so the only
//! errors worth reifying are payment-construction failures and wallet
//! I/O errors surfaced by `SingleNodePayment::{pay, verify}`.
//!
//! Callers that embed this crate (the node, the client) keep their own
//! broader error enums and convert via `From<ant_protocol::Error>`.

use std::fmt;

/// Result alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can be produced by `ant-protocol` APIs that do I/O or
/// construct payment proofs.
///
/// Wire-format errors (serialize/deserialize, size limits, address
/// mismatches) are reported via [`crate::chunk::ProtocolError`] because
/// they travel across the wire inside response messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A payment-construction or on-chain interaction failed.
    Payment(String),
    /// A cryptographic operation failed (key parsing, signing probe).
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payment(msg) => write!(f, "payment error: {msg}"),
            Self::Crypto(msg) => write!(f, "crypto error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}
