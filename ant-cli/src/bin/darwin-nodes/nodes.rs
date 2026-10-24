//! `dismiss`, `start`, `status` and `stop`: `ant node`'s of `ant` 0.3.9, naming this manager.

use clap::Args;
use colored::Colorize;

use ant_core::node::daemon::client;
use ant_core::node::daemon::health::{FleetHealth, HealthLevel};
use ant_core::node::types::{DaemonConfig, NodeStatus};

/// What `start` and `stop` say when the daemon isn't running.
const DAEMON_NOT_RUNNING: &str =
    "The daemon is not running. Start it first with: darwin-nodes daemon start";

/// What the commands say when no node is registered.
fn print_no_nodes() {
    println!(
        "{} No nodes registered. Add nodes first with: {}",
        "●".yellow(),
        "darwin-nodes add".cyan()
    );
}

#[derive(Args)]
pub struct DismissArgs {
    /// The ID of the node to remove from the registry. Its data folder is left where it is
    pub node_id: u32,
}

impl DismissArgs {
    pub async fn execute(self, json_output: bool) -> anyhow::Result<()> {
        let config = DaemonConfig::default();

        // Through the daemon when it is running, so its in-memory registry stays in step (it
        // refuses a running node); otherwise directly on the registry file. Either way only the
        // registry entry goes.
        let status = client::status(&config).await?;
        let result = if status.running {
            client::dismiss_node(&config, self.node_id).await?
        } else {
            ant_core::node::remove_node(self.node_id, &config.registry_path)?
        };

        if json_output {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "{} Dismissed node {} ({})",
                "✓".green().bold(),
                result.removed.id.to_string().bold(),
                result.removed.service_name.dimmed()
            );
        }

        Ok(())
    }
}

#[derive(Args)]
pub struct StartArgs {
    /// Start a specific node by service name (e.g., node1). If omitted, starts all nodes.
    #[arg(long)]
    pub service_name: Option<String>,
}

impl StartArgs {
    pub async fn execute(self, json_output: bool) -> anyhow::Result<()> {
        let config = DaemonConfig::default();

        let status = client::status(&config).await?;
        if !status.running {
            anyhow::bail!(DAEMON_NOT_RUNNING);
        }

        let Some(ref service_name) = self.service_name else {
            let result = client::start_all_nodes(&config).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }
            if !result.started.is_empty() {
                println!(
                    "{} Started {} node(s):",
                    "✓".green().bold(),
                    result.started.len().to_string().bold()
                );
                for node in &result.started {
                    println!(
                        "  {} {} ({}) — PID {}",
                        "●".green(),
                        node.service_name.bold(),
                        node.node_id.to_string().dimmed(),
                        node.pid.to_string().cyan()
                    );
                }
            }
            if !result.already_running.is_empty() {
                println!(
                    "{} Already running: {} node(s)",
                    "●".yellow(),
                    result.already_running.len().to_string().bold()
                );
                for id in &result.already_running {
                    println!("  {} Node {}", "─".dimmed(), id.to_string().dimmed());
                }
            }
            if !result.failed.is_empty() {
                println!(
                    "{} Failed to start {} node(s):",
                    "✗".red().bold(),
                    result.failed.len().to_string().bold()
                );
                for fail in &result.failed {
                    println!(
                        "  {} {} ({}) — {}",
                        "●".red(),
                        fail.service_name.bold(),
                        fail.node_id.to_string().dimmed(),
                        fail.error.red()
                    );
                }
            }
            if result.started.is_empty()
                && result.already_running.is_empty()
                && result.failed.is_empty()
            {
                print_no_nodes();
            }
            return Ok(());
        };

        // Resolve the node ID through the daemon API — the daemon owns the registry.
        let node_id = client::resolve_node_id_by_name(&config, service_name).await?;
        let result = client::start_node(&config, node_id).await?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "{} Node {} ({}) started — PID {}",
                "✓".green().bold(),
                result.service_name.bold(),
                result.node_id.to_string().dimmed(),
                result.pid.to_string().cyan()
            );
        }
        Ok(())
    }
}

#[derive(Args)]
pub struct StopArgs {
    /// Stop a specific node by service name (e.g., node1). If omitted, stops all nodes.
    #[arg(long)]
    pub service_name: Option<String>,
}

impl StopArgs {
    pub async fn execute(self, json_output: bool) -> anyhow::Result<()> {
        let config = DaemonConfig::default();

        let status = client::status(&config).await?;
        if !status.running {
            anyhow::bail!(DAEMON_NOT_RUNNING);
        }

        let Some(ref service_name) = self.service_name else {
            let result = client::stop_all_nodes(&config).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }
            if !result.stopped.is_empty() {
                println!(
                    "{} Stopped {} node(s):",
                    "✓".green().bold(),
                    result.stopped.len().to_string().bold()
                );
                for node in &result.stopped {
                    println!(
                        "  {} {} ({})",
                        "●".dimmed(),
                        node.service_name.bold(),
                        node.node_id.to_string().dimmed()
                    );
                }
            }
            if !result.already_stopped.is_empty() {
                println!(
                    "{} Already stopped: {} node(s)",
                    "●".yellow(),
                    result.already_stopped.len().to_string().bold()
                );
                for id in &result.already_stopped {
                    println!("  {} Node {}", "─".dimmed(), id.to_string().dimmed());
                }
            }
            if !result.failed.is_empty() {
                println!(
                    "{} Failed to stop {} node(s):",
                    "✗".red().bold(),
                    result.failed.len().to_string().bold()
                );
                for fail in &result.failed {
                    println!(
                        "  {} {} ({}) — {}",
                        "●".red(),
                        fail.service_name.bold(),
                        fail.node_id.to_string().dimmed(),
                        fail.error.red()
                    );
                }
            }
            if result.stopped.is_empty()
                && result.already_stopped.is_empty()
                && result.failed.is_empty()
            {
                print_no_nodes();
            }
            return Ok(());
        };

        // Resolve the node ID through the daemon API — the daemon owns the registry.
        let node_id = client::resolve_node_id_by_name(&config, service_name).await?;
        let result = client::stop_node(&config, node_id).await?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "{} Node {} ({}) stopped",
                "✓".green().bold(),
                result.service_name.bold(),
                result.node_id.to_string().dimmed()
            );
        }
        Ok(())
    }
}

#[derive(Args)]
pub struct StatusArgs {}

impl StatusArgs {
    pub async fn execute(self, json_output: bool) -> anyhow::Result<()> {
        let config = DaemonConfig::default();

        let daemon_status = client::status(&config).await?;
        let result = if daemon_status.running {
            client::node_status(&config).await?
        } else {
            ant_core::node::node_status_offline(&config.registry_path)?
        };

        // Fleet health is only known while the daemon is running (it reads the disk).
        let health = if daemon_status.running {
            client::fleet_health(&config).await.ok()
        } else {
            None
        };

        if json_output {
            let payload = serde_json::json!({
                "nodes": result.nodes,
                "total_running": result.total_running,
                "total_stopped": result.total_stopped,
                "health": health,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
            return Ok(());
        }

        if let Some(health) = &health {
            print_fleet_health(health);
        }
        if result.nodes.is_empty() {
            print_no_nodes();
            return Ok(());
        }

        println!(
            "  {:<4} {:<14} {:<18} {}",
            "ID".dimmed(),
            "Name".dimmed(),
            "Version".dimmed(),
            "Status".dimmed()
        );
        println!("  {}", "─".repeat(52).dimmed());

        for node in &result.nodes {
            let status_display = match node.status {
                NodeStatus::Running => format!("{} {}", "●".green(), "Running".green()),
                NodeStatus::Stopped => format!("{} {}", "●".dimmed(), "Stopped".dimmed()),
                NodeStatus::Starting => format!("{} {}", "●".yellow(), "Starting".yellow()),
                NodeStatus::Stopping => format!("{} {}", "●".yellow(), "Stopping".yellow()),
                NodeStatus::Errored => format!("{} {}", "●".red(), "Errored".red()),
                NodeStatus::Evicted => format!("{} {}", "●".magenta(), "Evicted".magenta()),
            };
            println!(
                "  {:<4} {:<14} {:<18} {}",
                node.node_id.to_string().bold(),
                node.name,
                node.version.dimmed(),
                status_display
            );
            // A marker an earlier manager left when it evicted the node: say so, and how to clear
            // it.
            if let Some(eviction) = &node.eviction {
                println!(
                    "       {}",
                    format!("Evicted by an earlier node manager: {}", eviction.reason).dimmed()
                );
                println!(
                    "       {} {}",
                    "dismiss with:".dimmed(),
                    format!("darwin-nodes dismiss {}", node.node_id).cyan()
                );
            }
        }

        if !daemon_status.running {
            println!();
            println!(
                "  {} Daemon is not running — all nodes shown as stopped.",
                "!".yellow().bold()
            );
            println!("  Start it with: {}", "darwin-nodes daemon start".cyan());
        }

        Ok(())
    }
}

/// Print the fleet health summary: an overall line, plus a detail line per non-green check.
fn print_fleet_health(health: &FleetHealth) {
    let (dot, label) = match health.overall {
        HealthLevel::Green => ("●".green(), "Healthy".green()),
        HealthLevel::Warning => ("●".yellow(), "Warning".yellow()),
        HealthLevel::Critical => ("●".red(), "Critical".red()),
    };
    println!("  {} Fleet health: {}", dot, label);

    for check in health
        .checks
        .iter()
        .filter(|c| c.level != HealthLevel::Green)
    {
        println!("    {} {}", "→".dimmed(), check.summary.dimmed());
    }
    println!();
}
