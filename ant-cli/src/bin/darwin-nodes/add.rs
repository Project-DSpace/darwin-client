use std::path::PathBuf;

use clap::Args;
use colored::Colorize;

use ant_core::node::daemon::client;
use ant_core::node::types::{
    AddNodeOpts, AddNodeResult, BinarySource, DaemonConfig, EvmNetwork, PortRange,
};

/// `ant node add` of `ant` 0.3.9, as the image runs it: the same arguments, but `--path` is
/// required and there is no download source (`--version`, `--url`), no `--upgrade-channel` and
/// no `--evm-network`.
#[derive(Args)]
pub struct AddArgs {
    /// Wallet address for node earnings (required)
    #[arg(long)]
    pub rewards_address: String,

    /// Number of nodes to add
    #[arg(long, default_value = "1")]
    pub count: u16,

    /// Port or port range for node(s) (e.g., 12000 or 12000-12004)
    #[arg(long)]
    pub node_port: Option<String>,

    /// Custom data directory prefix
    #[arg(long)]
    pub data_dir_path: Option<PathBuf>,

    /// Custom log directory prefix
    #[arg(long)]
    pub log_dir_path: Option<PathBuf>,

    /// Path to the node binary each node runs its own copy of (required: this manager downloads
    /// none)
    #[arg(long)]
    pub path: PathBuf,

    /// Bootstrap peer(s)
    #[arg(long, value_delimiter = ',')]
    pub bootstrap: Vec<String>,

    /// Environment variables for the node (KEY=VALUE format)
    #[arg(long, value_delimiter = ',')]
    pub env: Vec<String>,
}

impl AddArgs {
    pub async fn execute(self, json_output: bool) -> anyhow::Result<()> {
        let opts = self.to_add_node_opts()?;

        // Through the daemon when it is running, so its in-memory registry stays in step;
        // otherwise directly on the registry file.
        let config = DaemonConfig::default();
        let result = match client::status(&config).await {
            Ok(status) if status.running => client::add_node(&config, &opts).await?,
            _ => ant_core::node::add_local_nodes(opts, &config.registry_path).await?,
        };

        print_added(&result, json_output)
    }

    fn to_add_node_opts(&self) -> anyhow::Result<AddNodeOpts> {
        let node_port = self
            .node_port
            .as_deref()
            .map(str::parse::<PortRange>)
            .transpose()?;

        Ok(AddNodeOpts {
            count: self.count,
            rewards_address: self.rewards_address.clone(),
            node_port,
            data_dir_path: self.data_dir_path.clone(),
            log_dir_path: self.log_dir_path.clone(),
            binary_source: BinarySource::LocalPath(self.path.clone()),
            bootstrap_peers: self.bootstrap.clone(),
            env_variables: AddNodeOpts::parse_env_vars(&self.env)?,
            // None: each node follows its own default channel, as every node the image's `ant`
            // 0.3.9 added does (the image never passed one).
            upgrade_channel: None,
            // What `ant` 0.3.9 registered for every node the image added (its default), so the
            // node starts with `--evm-network arbitrum-one` as before. The image's payment
            // settings (ANT_EVM_RPC_URL, ANT_EVM_PAYMENT_TOKEN, ANT_EVM_PAYMENT_VAULT) override
            // it in the node, which is paid in DARWIN on Robinhood Chain: darwin-node's
            // `the_payment_settings_override_the_network_the_manager_passes` pins that.
            evm_network: EvmNetwork::ArbitrumOne,
        })
    }
}

fn print_added(result: &AddNodeResult, json_output: bool) -> anyhow::Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }

    println!(
        "{} Added {} node(s):",
        "✓".green().bold(),
        result.nodes_added.len().to_string().bold()
    );
    println!();
    for node in &result.nodes_added {
        println!(
            "  {} {}",
            "●".cyan(),
            format!("Node {} ({})", node.id, node.service_name).bold()
        );
        println!(
            "    {} {}",
            "Data".dimmed(),
            node.data_dir.display().to_string().white()
        );
        if let Some(ref log_dir) = node.log_dir {
            println!(
                "    {} {}",
                "Logs".dimmed(),
                log_dir.display().to_string().white()
            );
        }
        if let Some(port) = node.node_port {
            println!("    {} {}", "Port".dimmed(), port.to_string().cyan());
        }
        println!(
            "    {} {}",
            "Binary".dimmed(),
            node.binary_path.display().to_string().dimmed()
        );
        println!("    {} {}", "Version".dimmed(), node.version.green());
    }
    Ok(())
}
