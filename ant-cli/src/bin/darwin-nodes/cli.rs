use clap::{Parser, Subcommand};

use crate::add::AddArgs;
use crate::daemon::DaemonCommand;
use crate::nodes::{DismissArgs, StartArgs, StatusArgs, StopArgs};

/// `darwin-nodes 0.3.11+ds.4` on line 1, the git commit on line 2 (see build.rs).
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit ",
    env!("DARWIN_GIT_COMMIT")
);

#[derive(Parser)]
#[command(
    name = "darwin-nodes",
    version = VERSION,
    about = "Runs the Darwin storage nodes on this machine: the storage-node image's node manager",
    long_about = "Runs the Darwin storage nodes on this machine: the storage-node image's node \
                  manager. It adds nodes from a node binary already on the machine, starts, stops \
                  and supervises them (restarting them after a crash or an upgrade), and reports \
                  their status and the free disk space where their data is. It deletes no node's \
                  data, downloads nothing and forwards no logs."
)]
pub struct Cli {
    /// Output structured JSON instead of human-readable text
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Add nodes that run a node binary already on this machine (--path)
    Add(Box<AddArgs>),
    /// Manage the daemon that runs and supervises the nodes
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Remove a node from the registry. Its data folder is left where it is
    Dismiss(DismissArgs),
    /// Start node(s). With no arguments starts all nodes; use --service-name for a specific node.
    Start(StartArgs),
    /// Show the status of all registered nodes, and the free disk space where their data is
    Status(StatusArgs),
    /// Stop node(s). With no arguments stops all nodes; use --service-name for a specific node.
    Stop(StopArgs),
}
