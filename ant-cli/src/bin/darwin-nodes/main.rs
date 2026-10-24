//! `darwin-nodes`: the node manager of the storage-node image (darwin-node's `docker/`). It adds,
//! starts, stops and supervises the Darwin storage nodes on one machine, and serves their status,
//! with the registry, REST API and node start arguments of Autonomi's `ant node` 0.3.9, which the
//! image ran before.
//!
//! Only darwin-node's image build ships it, from a darwin-client commit pinned there. It is not
//! `darwin node`, which stays off in the darwin CLI, and it leaves out what that manager has:
//!
//! - it deletes no node's data: no disk-pressure eviction (removed from ant-core's manager for
//!   every build; the low-disk warning stays, as a report) and no reset;
//! - it downloads nothing: `add` takes a node binary already on the machine (`--path`);
//! - it forwards no logs: no `logs forward`, and its daemon serves no log-forwarding API.
//!
//! `pins.rs` and `ant-cli/tests/darwin_nodes.rs` hold it to that.

mod add;
mod cli;
mod daemon;
mod nodes;
#[cfg(test)]
mod pins;

use clap::Parser;

use cli::{Cli, Command};

/// The runtime `ant` 0.3.9 ran its daemon on: at least 4 worker threads whatever the CPU count,
/// so the supervisor's process scans and file reads don't hold up the API on a 1-vCPU server.
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // On the heap, as darwin's: a debug build's futures can be large for a main thread's stack.
    let code = match Box::pin(run()).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e:#}");
            1
        }
    };

    // Flush stdout before force-exit to ensure all output (especially JSON) is written.
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Force-exit rather than wait for the runtime's shutdown, as darwin does: everything has been
    // written by now.
    std::process::exit(code);
}

async fn run() -> anyhow::Result<()> {
    let Cli { json, command } = Cli::parse();
    match command {
        Command::Add(args) => args.execute(json).await,
        Command::Daemon { command } => command.execute(json).await,
        Command::Dismiss(args) => args.execute(json).await,
        Command::Start(args) => args.execute(json).await,
        Command::Status(args) => args.execute(json).await,
        Command::Stop(args) => args.execute(json).await,
    }
}
