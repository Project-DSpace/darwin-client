pub mod add;
pub mod daemon;
pub mod dismiss;
pub mod logs;
pub mod reset;
pub mod start;
pub mod status;
pub mod stop;

use clap::Subcommand;

use crate::commands::node::add::AddArgs;
use crate::commands::node::daemon::DaemonCommand;
use crate::commands::node::dismiss::DismissArgs;
use crate::commands::node::logs::LogsCommand;
use crate::commands::node::reset::ResetArgs;
use crate::commands::node::start::StartArgs;
use crate::commands::node::status::StatusArgs;
use crate::commands::node::stop::StopArgs;

/// Whether `darwin node` runs upstream's node manager. Off: it would install
/// Autonomi's ant-node from WithAutonomi's releases, which joins Autonomi's
/// network and is paid on Arbitrum, and its log forwarding ships node logs to
/// Autonomi's endpoint. Darwin storage nodes run from the storage-node image.
const NODE_MANAGER: bool = false;

/// Why every `darwin node` command is refused while [`NODE_MANAGER`] is off.
const NODE_MANAGER_OFF: &str = "`darwin node` is off in this build: it would install Autonomi's \
     ant-node, which joins Autonomi's network and is paid on Arbitrum, not Darwin. Darwin storage \
     nodes run from the storage-node image (see the darwin-node repository's docker/README.md). \
     Nodes added by an earlier build are managed with Autonomi's `ant`.";

/// Refuse every `darwin node` command, the hidden `daemon run` and any a
/// merge adds, while [`NODE_MANAGER`] is off: called before the command is
/// looked at, so nothing is downloaded, written, started or asked over the
/// network.
pub fn ensure_node_manager() -> anyhow::Result<()> {
    if !NODE_MANAGER {
        anyhow::bail!(NODE_MANAGER_OFF);
    }
    Ok(())
}

#[derive(Subcommand)]
pub enum NodeCommand {
    /// Add Autonomi ant-node instances to the registry (Autonomi's network, not Darwin's)
    Add(Box<AddArgs>),
    /// Manage the node daemon
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Dismiss an evicted node, removing it from the registry/list
    Dismiss(DismissArgs),
    /// Manage node log handling, including forwarding logs to Autonomi's beta endpoint
    Logs {
        #[command(subcommand)]
        command: LogsCommand,
    },
    /// Reset all node state (removes all data, logs, and clears the registry)
    Reset(ResetArgs),
    /// Start node(s). With no arguments starts all nodes; use --service-name for a specific node.
    Start(StartArgs),
    /// Show the status of all registered nodes
    Status(StatusArgs),
    /// Stop node(s). With no arguments stops all nodes; use --service-name for a specific node.
    Stop(StopArgs),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_manager_is_off() {
        const { assert!(!NODE_MANAGER) };
        let error = ensure_node_manager().unwrap_err().to_string();
        assert_eq!(error, NODE_MANAGER_OFF);
        assert!(error.contains("Autonomi's ant-node"), "{error}");
        assert!(error.contains("storage-node image"), "{error}");
    }
}
