//! Logging facade that compiles to no-ops when the `logging` feature is disabled.
//!
//! When the `logging` feature is enabled, this module re-exports the
//! [`tracing`] macros (`info!`, `warn!`, `debug!`, `error!`, `trace!`).
//!
//! When disabled, all macros expand to `()` — zero binary size overhead,
//! zero runtime cost. Argument expressions are **not evaluated**, so
//! `info!("{}", expensive_call())` costs nothing in release builds.

// ---- Feature enabled: re-export tracing ----
#[cfg(feature = "logging")]
pub use tracing::{debug, enabled, error, info, trace, warn, Level};

// ---- Feature disabled: no-op macros ----

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __protocol_log_noop_info {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __protocol_log_noop_warn {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __protocol_log_noop_debug {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __protocol_log_noop_error {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __protocol_log_noop_trace {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __protocol_log_noop_enabled {
    ($($arg:tt)*) => {
        false
    };
}

#[cfg(not(feature = "logging"))]
pub use __protocol_log_noop_debug as debug;
#[cfg(not(feature = "logging"))]
pub use __protocol_log_noop_enabled as enabled;
#[cfg(not(feature = "logging"))]
pub use __protocol_log_noop_error as error;
#[cfg(not(feature = "logging"))]
pub use __protocol_log_noop_info as info;
#[cfg(not(feature = "logging"))]
pub use __protocol_log_noop_trace as trace;
#[cfg(not(feature = "logging"))]
pub use __protocol_log_noop_warn as warn;

/// Stub for `tracing::Level` when logging is disabled.
#[cfg(not(feature = "logging"))]
#[allow(dead_code)]
pub struct Level;

#[cfg(not(feature = "logging"))]
#[allow(dead_code)]
impl Level {
    /// Debug level stub.
    pub const DEBUG: Self = Self;
    /// Info level stub.
    pub const INFO: Self = Self;
    /// Warn level stub.
    pub const WARN: Self = Self;
    /// Error level stub.
    pub const ERROR: Self = Self;
    /// Trace level stub.
    pub const TRACE: Self = Self;
}
