pub mod chunk;
pub mod file;
pub mod listings;
pub mod manifest;
pub mod pointer;
pub mod wallet;

pub use chunk::ChunkAction;
pub use file::FileAction;
pub use listings::{ListingArgs, ListingsArgs};
pub use manifest::ManifestAction;
pub use pointer::PointerAction;
pub use wallet::WalletAction;

use ant_core::data::Error as DataError;

/// Said after a payment error by a command that pays for single records:
/// the payment is journaled, so running the command again finds a payment
/// that went through instead of paying again, as an upload does.
const RUN_AGAIN: &str = "If the payment went through, run the same command again: it finds the \
                         payment on the chain and carries on without paying twice.";

/// The error of a command that pays for single records (`what` failed),
/// with [`RUN_AGAIN`] after a payment error.
pub(crate) fn paid_command_failed(what: &str, error: &DataError) -> anyhow::Error {
    match error {
        DataError::Payment(_) => anyhow::anyhow!("{what} failed: {error}\n{RUN_AGAIN}"),
        _ => anyhow::anyhow!("{what} failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payment error says that running the command again carries on
    /// without paying twice; any other error says only what failed.
    #[test]
    fn a_payment_error_says_to_run_the_same_command_again() {
        let error = DataError::Payment("error code -32603: internal error".into());
        let message = paid_command_failed("Chunk put", &error).to_string();
        assert_eq!(
            message,
            "Chunk put failed: payment error: error code -32603: internal error\n\
             If the payment went through, run the same command again: it finds the payment on \
             the chain and carries on without paying twice."
        );
        let error = DataError::InsufficientPeers("stored on 2 peers, need 4".into());
        let message = paid_command_failed("Chunk put", &error).to_string();
        assert!(message.starts_with("Chunk put failed: "), "{message}");
        assert!(!message.contains("run the same command again"), "{message}");
    }
}
