/// Cross-platform Autonomi client logic and browser WASM bindings.
pub mod browser;
#[cfg(feature = "native")]
pub mod channel;
pub mod network_defaults;

mod payment_policy;
mod quote_policy;
mod quote_validation;
mod record;
mod transfer_policy;

mod client_engine;
#[cfg(test)]
mod lock_pins;

// This network's price multiplier is in vendor/ant-protocol, which
// `[patch.crates-io]` puts in place of crates.io's ant-protocol 5.0.0. Built
// against crates.io's copy (a project that takes ant-core by git without
// repeating the patch; README, "Rust Library API"), ant-core would check and
// pay quotes at Autonomi's prices. It fails to compile here instead:
// `FULL_RECORD_BYTES` is in the vendored copy only (its VENDORED.md).
const _: u64 = ant_protocol::payment::pricing::FULL_RECORD_BYTES;

#[cfg(feature = "native")]
pub mod config;
pub mod data;
/// Listed files: the envelope format, listings and the listings protocol.
pub use ant_listings;
#[cfg(feature = "native")]
pub mod datamap_file;
#[cfg(feature = "native")]
pub mod error;
#[cfg(feature = "native")]
pub mod install;
#[cfg(feature = "native")]
pub mod node;
mod runtime;
#[cfg(feature = "native")]
pub mod update;

#[cfg(all(target_arch = "wasm32", not(feature = "browser-wasm")))]
compile_error!("WASM builds of ant-core require the `browser-wasm` feature");
