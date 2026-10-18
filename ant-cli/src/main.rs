mod cli;
mod commands;
#[cfg(test)]
mod darwin_pins;
mod progress;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use ant_core::data::{
    peer_cache::{self, BootstrapAddressFilter},
    Client, ClientConfig, CoreNodeConfig, DevnetManifest, EvmNetwork, IPDiversityConfig, MultiAddr,
    NodeMode, P2PNode, Wallet, MAX_WIRE_MESSAGE_SIZE,
};
use cli::{Cli, Commands};

/// Force at least 4 worker threads regardless of CPU count.
///
/// On small VMs (1-2 vCPU), the default `num_cpus` gives only 1-2 worker
/// threads.  The NAT traversal poll() function does synchronous work
/// (parking_lot locks, DashMap iteration) that blocks its worker thread.
/// With only 1 worker, this freezes the entire runtime — timers stop,
/// keepalives can't fire, and connections die silently.
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // On the heap: on the main thread's stack, a debug build overflowed the
    // 1 MB stack a Windows main thread has on every run, `--version`
    // included.
    let code = match Box::pin(run()).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e:#}");
            1
        }
    };

    // Flush stdout before force-exit to ensure all output (especially JSON) is written.
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Force-exit to avoid hanging on tokio runtime shutdown.
    // Open QUIC connections and pending background tasks (DHT, keep-alive)
    // block the runtime's graceful shutdown indefinitely. All data has been
    // persisted / printed by this point, so there is nothing left to clean up.
    std::process::exit(code);
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Privacy by design: no logs unless the user explicitly opts in with -v
    // or by setting RUST_LOG. A decentralized network client must not emit
    // metadata by default.
    let needs_tracing = !matches!(cli.command, Commands::Node { .. });
    if needs_tracing {
        let filter = match (EnvFilter::try_from_default_env().ok(), cli.verbose) {
            (Some(f), _) => Some(f),
            (None, 0) => None,
            (None, 1) => Some(EnvFilter::new(verbose_filter("info"))),
            (None, 2) => Some(EnvFilter::new(verbose_filter("debug"))),
            (None, _) => Some(EnvFilter::new("trace")),
        };
        if let Some(filter) = filter {
            tracing_subscriber::registry()
                .with(fmt::layer().with_writer(progress::ProgressAwareWriter))
                .with(filter)
                .init();
        }
    }

    // Separate the command from the rest of the CLI args to avoid partial-move issues.
    // `verbose` was consumed by the tracing filter init above.
    let Cli {
        json,
        command,
        bootstrap,
        devnet_manifest,
        allow_loopback,
        ipv4_only,
        quote_timeout_secs,
        store_timeout_secs,
        chunk_get_timeout_secs,
        verbose: _,
        evm_network,
        max_chunk_price,
        quote_concurrency,
        store_concurrency,
    } = cli;

    // Shared context for data commands that need EVM / bootstrap info.
    let data_ctx = DataCliContext {
        bootstrap,
        devnet_manifest,
        allow_loopback,
        ipv4_only,
        quote_timeout_secs,
        store_timeout_secs,
        chunk_get_timeout_secs,
        evm_network,
        max_chunk_price,
        quote_concurrency,
        store_concurrency,
    };

    match command {
        Commands::Node { command } => {
            // Off in this build: every node command is refused here, before
            // any download, registry write, daemon or network call.
            commands::node::ensure_node_manager()?;
            // Delegate to existing node management commands
            match command {
                commands::node::NodeCommand::Add(args) => {
                    args.execute(json).await?;
                }
                commands::node::NodeCommand::Daemon { command } => {
                    command.execute(json).await?;
                }
                commands::node::NodeCommand::Dismiss(args) => {
                    args.execute(json).await?;
                }
                commands::node::NodeCommand::Logs { command } => {
                    command.execute(json).await?;
                }
                commands::node::NodeCommand::Reset(args) => {
                    args.execute(json).await?;
                }
                commands::node::NodeCommand::Start(args) => {
                    args.execute(json).await?;
                }
                commands::node::NodeCommand::Status(args) => {
                    args.execute(json).await?;
                }
                commands::node::NodeCommand::Stop(args) => {
                    args.execute(json).await?;
                }
            }
        }
        Commands::Wallet { action } => {
            // Wallet commands don't need network connection
            let private_key = require_secret_key()?;
            let (network, _) = resolve_evm_network_and_manifest(&data_ctx)?;
            let wallet = create_wallet(&private_key, network, &data_ctx)?;
            action.execute(wallet).await?;
        }
        Commands::File { action } => {
            // Bad upload choices fail before SECRET_KEY or the network.
            action.validate()?;
            if !action.needs_network() {
                // `prove` is offline; `verify` reads only the payment chain.
                return action
                    .execute_offline(json, || {
                        resolve_evm_network_and_manifest(&data_ctx).map(|(network, _)| network)
                    })
                    .await;
            }
            let needs_wallet = matches!(action, commands::data::FileAction::Upload { .. });
            // Extract per-upload overrides BEFORE building the client
            // so the adaptive controller picks them up at construction.
            let (store_timeout_override, store_concurrency_override) = action.upload_overrides();
            let client = build_data_client(
                &data_ctx,
                needs_wallet,
                json,
                store_timeout_override,
                store_concurrency_override,
            )
            .await?;
            let token = token_symbol(&data_ctx);
            let result = action.execute(&client, json, &token).await;
            // Persist whatever the controller learned this run, even
            // on error — partial signal is still better than cold next
            // time. Drop will also fire as a backstop.
            client.save_peer_cache().await;
            client.save_adaptive_snapshot();
            result?;
        }
        Commands::Chunk { action } => {
            let needs_wallet = matches!(action, commands::data::ChunkAction::Put { .. });
            let client = build_data_client(&data_ctx, needs_wallet, json, None, None).await?;
            let result = action.execute(&client).await;
            client.save_peer_cache().await;
            client.save_adaptive_snapshot();
            result?;
        }
        Commands::Pointer { action } => {
            if !action.needs_network() {
                return action.execute_offline(json);
            }
            let client =
                build_data_client(&data_ctx, action.needs_wallet(), json, None, None).await?;
            let result = action.execute(&client, json).await;
            client.save_peer_cache().await;
            client.save_adaptive_snapshot();
            result?;
        }
        Commands::Listings(args) => {
            // A --state or --carry file that can't be used fails before the
            // network.
            let earlier = args.load_earlier(json)?;
            let client = build_data_client(&data_ctx, false, json, None, None).await?;
            let (network, _) = resolve_evm_network_and_manifest(&data_ctx)?;
            let chain = ant_core::data::ListingChain::new(&network)?;
            let result = args.execute(&client, &chain, json, earlier).await;
            client.save_peer_cache().await;
            client.save_adaptive_snapshot();
            result?;
        }
        Commands::Listing(args) => {
            let client = build_data_client(&data_ctx, false, json, None, None).await?;
            let (network, _) = resolve_evm_network_and_manifest(&data_ctx)?;
            let chain = ant_core::data::ListingChain::new(&network)?;
            let result = args.execute(&client, &chain, json).await;
            client.save_peer_cache().await;
            client.save_adaptive_snapshot();
            result?;
        }
        Commands::Manifest { action } => {
            // Bad upload choices fail before SECRET_KEY or the network, as
            // for `darwin file upload`.
            action.validate()?;
            if !action.needs_network() {
                return action.execute_offline(json);
            }
            let client =
                build_data_client(&data_ctx, action.needs_wallet(), json, None, None).await?;
            let result = action.execute(&client, json).await;
            client.save_peer_cache().await;
            client.save_adaptive_snapshot();
            result?;
        }
        Commands::Update(args) => {
            args.execute(json).await?;
        }
    }

    Ok(())
}

/// Shared context for data commands extracted from CLI args.
struct DataCliContext {
    bootstrap: Vec<MultiAddr>,
    devnet_manifest: Option<PathBuf>,
    allow_loopback: bool,
    ipv4_only: bool,
    quote_timeout_secs: u64,
    store_timeout_secs: Option<u64>,
    chunk_get_timeout_secs: Option<u64>,
    evm_network: Option<String>,
    max_chunk_price: Option<ant_core::data::U256>,
    quote_concurrency: Option<usize>,
    store_concurrency: Option<usize>,
}

/// Build a data client with wallet if SECRET_KEY is set.
///
/// Per-action overrides (`store_timeout_override`,
/// `store_concurrency_override`) are applied BEFORE constructing the
/// adaptive controller, so the controller actually honors them as
/// caps. Mutating `client.config_mut()` after construction would be a
/// no-op for the controller (the controller is built once at
/// `Client::from_node`).
async fn build_data_client(
    ctx: &DataCliContext,
    needs_wallet: bool,
    quiet: bool,
    store_timeout_override: Option<u64>,
    store_concurrency_override: Option<usize>,
) -> anyhow::Result<Client> {
    let private_key = std::env::var("SECRET_KEY")
        .ok()
        .map(|k| k.strip_prefix("0x").unwrap_or(&k).to_string());

    if needs_wallet && private_key.is_none() {
        anyhow::bail!("SECRET_KEY environment variable required for this operation");
    }

    let manifest = load_manifest(ctx)?;
    let bootstrap =
        ant_core::config::resolve_bootstrap_multiaddrs(&ctx.bootstrap, manifest.as_ref())?;
    // Explicit network selectors should be isolated from the general client
    // peer cache. `--bootstrap` and `--devnet-manifest` both mean "use exactly
    // this network entrypoint", so cached public-network peers must not be
    // mixed in or saved back from that run.
    let use_peer_cache = ctx.devnet_manifest.is_none() && ctx.bootstrap.is_empty();

    // Connection phase with animated spinner showing peer discovery in real-time.
    // The spinner is the user-facing UI; tracing::info! provides log-level visibility
    // when `-v` is set.
    info!("Connecting to the Darwin network");
    let node = if quiet {
        create_client_node(
            &bootstrap,
            ctx.allow_loopback,
            ctx.ipv4_only,
            use_peer_cache,
        )
        .await?
    } else {
        let spinner = progress::new_spinner("Connecting to the Darwin network...");

        let node = match create_client_node_raw(
            &bootstrap,
            ctx.allow_loopback,
            ctx.ipv4_only,
            use_peer_cache,
        )
        .await
        {
            Ok(n) => n,
            Err(e) => {
                spinner.finish_and_clear();
                return Err(e);
            }
        };

        // Poll peer count during node.start() to show real-time discovery.
        // The spinner reflects every change; `info!` only fires on each new
        // peer-count milestone to avoid flooding the log.
        let spinner_clone = spinner.clone();
        let node_clone = node.clone();
        let poll_handle = tokio::spawn(async move {
            let mut last_logged = 0usize;
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let count = node_clone.connected_peers().await.len();
                if count > 0 {
                    spinner_clone.set_message(format!(
                        "Connecting to the Darwin network... (found {count} peers)"
                    ));
                }
                if count > last_logged {
                    info!("Discovered {count} peer(s)");
                    last_logged = count;
                }
            }
        });

        let start_result = node.start().await;
        poll_handle.abort();
        spinner.finish_and_clear();

        start_result.map_err(|e| anyhow::anyhow!("Failed to start P2P node: {e}"))?;

        let peers = node.connected_peers().await.len();
        if use_peer_cache {
            promote_client_peer_cache(&node).await;
        }
        info!("Connected to the Darwin network ({peers} peers)");
        eprintln!("Connected to the Darwin network (found {peers} peers)");
        node
    };

    let mut config = ClientConfig {
        quote_timeout_secs: ctx.quote_timeout_secs,
        max_chunk_price: ctx.max_chunk_price,
        ..Default::default()
    };
    if let Some(t) = ctx.store_timeout_secs {
        config.store_timeout_secs = t;
    }
    if let Some(t) = ctx.chunk_get_timeout_secs {
        config.chunk_get_timeout_secs = t;
    }
    // Legacy default values are treated as "not pinned" by build_controller
    // (so the default ClientConfig doesn't silently lower the new
    // adaptive ceilings). Mirror that here so the deprecation warning
    // doesn't lie when a user passes a value equal to the legacy default.
    const LEGACY_QUOTE_DEFAULT: usize = 32;
    const LEGACY_STORE_DEFAULT: usize = 8;
    if let Some(concurrency) = ctx.quote_concurrency {
        if concurrency == LEGACY_QUOTE_DEFAULT {
            eprintln!(
                "warning: --quote-concurrency={concurrency} matches the legacy \
                 default and is silently ignored by the adaptive controller. \
                 Pass a different value to actually cap the quote channel."
            );
        } else {
            eprintln!(
                "warning: --quote-concurrency is deprecated; the adaptive controller \
                 sizes quote concurrency from observed signals. Your value \
                 ({concurrency}) caps the quote channel only (store and download \
                 are unaffected) and will be removed in a future release."
            );
        }
        config.quote_concurrency = concurrency;
    }
    if let Some(concurrency) = ctx.store_concurrency {
        if concurrency == LEGACY_STORE_DEFAULT {
            eprintln!(
                "warning: --store-concurrency={concurrency} matches the legacy \
                 default and is silently ignored by the adaptive controller. \
                 Pass a different value to actually cap the store channel."
            );
        } else {
            eprintln!(
                "warning: --store-concurrency is deprecated; the adaptive controller \
                 sizes store concurrency from observed signals. Your value \
                 ({concurrency}) caps the store channel only (quote and download \
                 are unaffected) and will be removed in a future release."
            );
        }
        config.store_concurrency = concurrency;
    }
    // Per-action overrides (e.g. `darwin file upload --store-concurrency`)
    // applied here, BEFORE Client::from_node so the adaptive
    // controller actually picks them up. Mutating `config_mut()` after
    // construction is a no-op for the controller's per-channel max.
    if let Some(t) = store_timeout_override {
        config.store_timeout_secs = t;
    }
    if let Some(c) = store_concurrency_override {
        eprintln!(
            "warning: --store-concurrency on upload is deprecated; the \
             adaptive controller sizes store concurrency from observed \
             signals. Your value ({c}) caps the store channel only and \
             will be removed in a future release."
        );
        config.store_concurrency = c;
    }

    let peer_cache_path = use_peer_cache.then(peer_cache::cache_path).flatten();
    let mut client = data_client(node, config, peer_cache_path, &bootstrap);

    if needs_wallet {
        let key = private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SECRET_KEY environment variable required"))?;
        let network = resolve_evm_network(ctx.evm_network.as_deref(), manifest.as_ref())?;
        let wallet = create_wallet(key, network, ctx)?;
        info!("Wallet configured for EVM payments");
        client = client.with_wallet(wallet);
    }

    Ok(client)
}

/// The client a data command runs on `node`. Its reads also ask the resolved
/// bootstrap peers that carry a peer ID (the bundled seeds do), the nine
/// nearest each address read, not the node's own bootstrap list, which also
/// holds cached peers.
fn data_client(
    node: Arc<P2PNode>,
    config: ClientConfig,
    peer_cache_path: Option<PathBuf>,
    bootstrap: &[MultiAddr],
) -> Client {
    Client::from_node_with_peer_cache(node, config, peer_cache_path).with_bootstrap_peers(bootstrap)
}

/// Build the EnvFilter directives string for `-v` / `-vv`.
///
/// Targets cover ant-cli/ant-core plus the network-layer crates (ant_node, evmlib,
/// saorsa_core, saorsa_transport, saorsa_pqc) so that peer discovery / connection
/// events are visible at info/debug levels.
fn verbose_filter(level: &str) -> String {
    [
        "ant_cli",
        "ant_core",
        "ant_node",
        "evmlib",
        "saorsa_core",
        "saorsa_transport",
        "saorsa_pqc",
    ]
    .iter()
    .map(|t| format!("{t}={level}"))
    .collect::<Vec<_>>()
    .join(",")
}

fn require_secret_key() -> anyhow::Result<String> {
    std::env::var("SECRET_KEY")
        .map_err(|_| anyhow::anyhow!("SECRET_KEY environment variable required"))
}

/// The wallet signs only for the payment network's chain: the bundled
/// network's, or with `--evm-network local` the devnet manifest's
/// `evm.chain_id`. A network without one signs for whatever chain its RPC
/// reports.
fn create_wallet(
    private_key: &str,
    network: EvmNetwork,
    ctx: &DataCliContext,
) -> anyhow::Result<Wallet> {
    let chain_id = match (ctx.evm_network.as_deref(), &ctx.devnet_manifest) {
        (Some("local"), Some(path)) => {
            ant_core::config::manifest_chain_id(&std::fs::read_to_string(path)?)?
        }
        _ => ant_core::config::chain_id(&network),
    };
    ant_core::config::wallet(network, private_key, chain_id)
        .map_err(|e| anyhow::anyhow!("Failed to create wallet: {e}"))
}

/// Load and parse the devnet manifest once (if configured).
fn load_manifest(ctx: &DataCliContext) -> anyhow::Result<Option<DevnetManifest>> {
    if let Some(ref manifest_path) = ctx.devnet_manifest {
        let data = std::fs::read_to_string(manifest_path)?;
        Ok(Some(serde_json::from_str(&data)?))
    } else {
        Ok(None)
    }
}

fn resolve_evm_network_and_manifest(
    ctx: &DataCliContext,
) -> anyhow::Result<(EvmNetwork, Option<DevnetManifest>)> {
    let manifest = load_manifest(ctx)?;
    let network = resolve_evm_network(ctx.evm_network.as_deref(), manifest.as_ref())?;
    Ok((network, manifest))
}

/// The symbol of the selected payment network's token, which costs are
/// shown in. A network that can't be resolved here (the command reports why
/// if it needs one) gets the neutral word ant-core uses for unknown networks.
fn token_symbol(ctx: &DataCliContext) -> String {
    let manifest = load_manifest(ctx).ok().flatten();
    match ant_core::config::resolve_evm_network(ctx.evm_network.as_deref(), manifest.as_ref()) {
        Ok(network) => ant_core::config::token_symbol(&network),
        Err(_) => "tokens".to_string(),
    }
}

/// Resolve the EVM network through ant-core, with a CLI-side warning for
/// the one remaining silent-discard path: a devnet manifest that carries
/// an EVM block while the bundled network is selected (V2-471).
fn resolve_evm_network(
    evm_network: Option<&str>,
    manifest: Option<&DevnetManifest>,
) -> anyhow::Result<EvmNetwork> {
    if let (Some(m), Some(name)) = (manifest, evm_network) {
        if m.evm.is_some() && name != "local" {
            eprintln!(
                "warning: the devnet manifest contains an EVM block, but \
                 --evm-network={name} selects the bundled network; the \
                 manifest's EVM config is ignored. Pass --evm-network local \
                 to use it."
            );
        }
    }
    Ok(ant_core::config::resolve_evm_network(
        evm_network,
        manifest,
    )?)
}

async fn create_client_node(
    bootstrap: &[MultiAddr],
    allow_loopback: bool,
    ipv4_only: bool,
    use_peer_cache: bool,
) -> anyhow::Result<Arc<P2PNode>> {
    let node = create_client_node_raw(bootstrap, allow_loopback, ipv4_only, use_peer_cache).await?;
    node.start()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start P2P node: {e}"))?;
    if use_peer_cache {
        promote_client_peer_cache(&node).await;
    }
    Ok(node)
}

/// Create a P2P node without starting it (for spinner polling during start).
async fn create_client_node_raw(
    bootstrap: &[MultiAddr],
    allow_loopback: bool,
    ipv4_only: bool,
    use_peer_cache: bool,
) -> anyhow::Result<Arc<P2PNode>> {
    let mut core_config = CoreNodeConfig::builder()
        .port(0)
        .ipv6(!ipv4_only)
        .local(allow_loopback)
        .mode(NodeMode::Client)
        .max_message_size(MAX_WIRE_MESSAGE_SIZE)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create core config: {e}"))?;

    // Clients never enforce IP-diversity limits: they don't host data and
    // their routing table exists only to find peers, not to be defended
    // against Sybil clustering. Strict per-IP / per-subnet caps would
    // silently drop legitimate testnet peers that share an IP or /24.
    core_config.diversity_config = Some(IPDiversityConfig::permissive());

    let dht_k_value = core_config.dht_config.k_value;
    let cache_path = use_peer_cache.then(peer_cache::cache_path).flatten();
    let cache_address_filter = if ipv4_only {
        BootstrapAddressFilter::Ipv4Only
    } else {
        BootstrapAddressFilter::All
    };
    let cached_bootstrap_peers = cache_path
        .as_deref()
        .map(|path| {
            peer_cache::cached_bootstrap_peers_with_filter(path, dht_k_value, cache_address_filter)
        })
        .unwrap_or_default();

    core_config.bootstrap_peers =
        peer_cache::select_bootstrap_peers(cached_bootstrap_peers, bootstrap.iter().cloned());

    let node = P2PNode::new(core_config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create P2P node: {e}"))?;

    Ok(Arc::new(node))
}

async fn promote_client_peer_cache(node: &P2PNode) {
    let Some(cache_path) = peer_cache::cache_path() else {
        return;
    };
    peer_cache::promote_connected_direct_peers(node, &cache_path, node.dht().k_value()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolved seeds reach the client's reads. The node is never
    /// started, so nothing is dialled.
    #[tokio::test]
    async fn a_data_client_reads_from_the_resolved_bootstrap_peers() {
        let seeds: Vec<MultiAddr> = [
            format!("/ip4/127.0.0.1/udp/10000/quic/p2p/{}", "ab".repeat(32)),
            "/ip4/127.0.0.1/udp/10001/quic".to_string(),
        ]
        .iter()
        .map(|seed| seed.parse().expect("a QUIC multiaddress"))
        .collect();
        let node = create_client_node_raw(&[], true, true, false)
            .await
            .expect("a client node");
        let client = data_client(node, ClientConfig::default(), None, &seeds);
        assert_eq!(client.network().bootstrap_peers(), &seeds[..]);
    }
}
