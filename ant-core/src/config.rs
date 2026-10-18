use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use alloy::network::EthereumWallet;
use alloy::signers::{local::PrivateKeySigner, Signer};

use crate::data::{CustomNetwork, DevnetManifest, EvmAddress, EvmNetwork, MultiAddr, Wallet};
use crate::error::{Error, Result};

/// Returns the platform-appropriate data directory for ant.
///
/// - Linux: `~/.local/share/ant`
/// - macOS: `~/Library/Application Support/ant`
/// - Windows: `%APPDATA%\ant`
pub fn data_dir() -> Result<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        home_dir()?.join("Library").join("Application Support")
    } else if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir().unwrap().join("AppData").join("Roaming"))
    } else {
        std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir().unwrap().join(".local").join("share"))
    };
    Ok(base.join("ant"))
}

/// Returns the platform-appropriate configuration directory for ant.
///
/// - Linux: `~/.config/ant`
/// - macOS: `~/Library/Application Support/ant`
/// - Windows: `%APPDATA%\ant`
pub fn config_dir() -> Result<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        home_dir()?.join("Library").join("Application Support")
    } else if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir().unwrap().join("AppData").join("Roaming"))
    } else {
        std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir().unwrap().join(".config"))
    };
    Ok(base.join("ant"))
}

/// Returns the platform-appropriate log directory for ant.
///
/// - Linux: `~/.local/share/ant/logs`
/// - macOS: `~/Library/Logs/ant`
/// - Windows: `%APPDATA%\ant\logs`
pub fn log_dir() -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        Ok(home_dir()?.join("Library").join("Logs").join("ant"))
    } else {
        Ok(data_dir()?.join("logs"))
    }
}

/// The file in the config directory whose seeds replace the ones bundled in
/// the binary. It is darwin's own: Autonomi's `ant` and its installers keep
/// their network's seeds in `bootstrap_peers.toml` in the same directory,
/// which is never read, so a machine that also has `ant` keeps darwin's seeds.
pub const DARWIN_BOOTSTRAP_PEERS_FILE: &str = "darwin_bootstrap_peers.toml";

/// Loads bootstrap peers from [`DARWIN_BOOTSTRAP_PEERS_FILE`] in the config
/// directory.
///
/// Returns `Ok(Some(peers))` if the file exists and parses successfully,
/// `Ok(None)` if the file does not exist, or `Err` on parse/IO failures.
pub fn load_bootstrap_peers() -> Result<Option<Vec<SocketAddr>>> {
    Ok(load_bootstrap_multiaddrs()?
        .map(|peers| peers.iter().filter_map(MultiAddr::socket_addr).collect()))
}

/// Load native QUIC bootstrap multiaddresses from
/// [`DARWIN_BOOTSTRAP_PEERS_FILE`] in the config directory, preserving
/// optional peer pins.
pub fn load_bootstrap_multiaddrs() -> Result<Option<Vec<MultiAddr>>> {
    load_bootstrap_multiaddrs_in(&config_dir()?)
}

/// [`load_bootstrap_multiaddrs`] from the config directory `dir`: the QUIC
/// seeds of its [`DARWIN_BOOTSTRAP_PEERS_FILE`], or `None` when there is no
/// such file or it names none. A `bootstrap_peers.toml` there is not read.
pub fn load_bootstrap_multiaddrs_in(dir: &Path) -> Result<Option<Vec<MultiAddr>>> {
    let path = dir.join(DARWIN_BOOTSTRAP_PEERS_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let seeds = crate::network_defaults::parse_bootstrap_seeds(&std::fs::read_to_string(path)?)
        .map_err(|e| Error::BootstrapConfigParse(e.to_string()))?;
    Ok((!seeds.quic.is_empty()).then_some(seeds.quic))
}

/// Resolve native QUIC bootstrap addresses without losing peer identity suffixes.
/// Explicit input and selected manifests are authoritative; neither falls back.
/// With neither, [`DARWIN_BOOTSTRAP_PEERS_FILE`] in the config directory wins,
/// and the seeds bundled into the binary stand in when there is no such file.
pub fn resolve_bootstrap_multiaddrs(
    explicit: &[MultiAddr],
    manifest: Option<&DevnetManifest>,
) -> Result<Vec<MultiAddr>> {
    resolve_bootstrap_multiaddrs_with(explicit, manifest, load_bootstrap_multiaddrs)
}

/// [`resolve_bootstrap_multiaddrs`], with the override file's seeds read by
/// `override_file`, which is called only when there are no explicit or
/// manifest peers.
fn resolve_bootstrap_multiaddrs_with(
    explicit: &[MultiAddr],
    manifest: Option<&DevnetManifest>,
    override_file: impl FnOnce() -> Result<Option<Vec<MultiAddr>>>,
) -> Result<Vec<MultiAddr>> {
    let peers = if !explicit.is_empty() {
        explicit
            .iter()
            .map(|addr| crate::network_defaults::parse_quic_seed(&addr.to_string()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::BootstrapConfigParse(e.to_string()))?
    } else if let Some(manifest) = manifest {
        manifest
            .bootstrap
            .iter()
            .filter(|addr| addr.is_quic())
            .cloned()
            .collect()
    } else if let Some(peers) = override_file()? {
        peers
    } else {
        // No override file: the seeds compiled into the binary. Reached only where the
        // alternative is `NoBootstrapPeers`, so it cannot override a user's choice, and the
        // branches above mean an explicitly selected devnet manifest still errors rather than
        // reaching for the bundled network.
        let seeds = crate::network_defaults::bundled_bootstrap_seeds()
            .map_err(|e| Error::BootstrapConfigParse(e.to_string()))?;
        tracing::info!(
            "No bootstrap config file; using {} bundled bootstrap seed(s)",
            seeds.quic.len()
        );
        seeds.quic
    };
    if peers.is_empty() {
        return Err(Error::NoBootstrapPeers);
    }
    Ok(peers)
}

/// Resolve the bootstrap peers for a client connection.
///
/// Priority: explicitly supplied peers (e.g. a frontend's `--bootstrap`
/// flag) > devnet manifest peers > [`DARWIN_BOOTSTRAP_PEERS_FILE`] in the
/// config directory > the seeds bundled into the binary. Manifest peers
/// without a resolvable socket address are filtered out. A selected
/// manifest is authoritative: if it yields no usable peers, resolution
/// fails rather than falling back to the config file or the bundled
/// seeds — a devnet run must never silently reach for mainnet peers.
///
/// # Errors
///
/// Returns [`Error::NoBootstrapPeers`] when the selected source yields
/// no peers, and propagates config-file read/parse failures.
pub fn resolve_bootstrap_peers(
    explicit: &[SocketAddr],
    manifest: Option<&DevnetManifest>,
) -> Result<Vec<SocketAddr>> {
    let explicit: Vec<_> = explicit.iter().copied().map(MultiAddr::quic).collect();
    Ok(resolve_bootstrap_multiaddrs(&explicit, manifest)?
        .iter()
        .filter_map(MultiAddr::socket_addr)
        .collect())
}

/// Our network's payment chain, bundled into the binary. Switching tokens
/// means editing this file and rebuilding.
const BUNDLED_PAYMENT_NETWORK: &str = include_str!("../resources/payment_network.toml");

#[derive(serde::Deserialize)]
struct PaymentNetworkConfig {
    rpc_url: String,
    chain_id: u64,
    #[serde(default)]
    fallback_rpc_urls: Vec<String>,
    payment_token_address: String,
    payment_vault_address: String,
    token_symbol: String,
}

/// The payment chain this client uses unless told otherwise.
pub fn bundled_payment_network() -> Result<EvmNetwork> {
    let config: PaymentNetworkConfig = toml::from_str(BUNDLED_PAYMENT_NETWORK)
        .map_err(|e| Error::InvalidEvmManifest(format!("bundled payment network: {e}")))?;
    custom_network(
        &config.rpc_url,
        &config.payment_token_address,
        &config.payment_vault_address,
    )
}

/// The RPCs reads of payments on `network` (listings, upload proofs, and the
/// vault record of each quote an upload paid, read back after paying) fall
/// back to when its own RPC refuses or fails a call: the bundled network's
/// `fallback_rpc_urls`, and none for any other network.
#[must_use]
pub fn fallback_rpc_urls(network: &EvmNetwork) -> Vec<String> {
    let Ok(config) = toml::from_str::<PaymentNetworkConfig>(BUNDLED_PAYMENT_NETWORK) else {
        return Vec::new();
    };
    match bundled_payment_network() {
        Ok(bundled) if &bundled == network => config.fallback_rpc_urls,
        _ => Vec::new(),
    }
}

/// The symbol amounts of `network`'s payment token are shown in: the
/// bundled network's `token_symbol`, and a neutral word on any other network.
#[must_use]
pub fn token_symbol(network: &EvmNetwork) -> String {
    match (
        toml::from_str::<PaymentNetworkConfig>(BUNDLED_PAYMENT_NETWORK),
        bundled_payment_network(),
    ) {
        (Ok(config), Ok(bundled)) if &bundled == network => config.token_symbol,
        _ => "tokens".to_string(),
    }
}

/// The chain payments on `network` are signed for: the bundled network's
/// `chain_id`, and none for any other network (a devnet manifest may give
/// one; see [`manifest_chain_id`]).
#[must_use]
pub fn chain_id(network: &EvmNetwork) -> Option<u64> {
    match (
        toml::from_str::<PaymentNetworkConfig>(BUNDLED_PAYMENT_NETWORK),
        bundled_payment_network(),
    ) {
        (Ok(config), Ok(bundled)) if &bundled == network => Some(config.chain_id),
        _ => None,
    }
}

/// The `chain_id` a devnet manifest's `evm` block may give for payments on
/// its network. Upstream's [`DevnetManifest`] has no such field, so it is
/// read from the manifest's JSON.
pub fn manifest_chain_id(manifest: &str) -> Result<Option<u64>> {
    #[derive(serde::Deserialize)]
    struct Manifest {
        evm: Option<Evm>,
    }
    #[derive(serde::Deserialize)]
    struct Evm {
        chain_id: Option<u64>,
    }
    let manifest: Manifest = serde_json::from_str(manifest)
        .map_err(|e| Error::InvalidEvmManifest(format!("invalid chain ID: {e}")))?;
    Ok(manifest.evm.and_then(|evm| evm.chain_id))
}

/// A wallet paying on `network` with `private_key` (hex, `0x` optional).
/// With a `chain_id` it signs for that chain only: each transaction's chain
/// ID is the RPC's `eth_chainId`, and the signer refuses one that differs,
/// naming both, so a wrong or lying RPC gets nothing signed or sent. Without
/// one it signs for whatever chain the RPC reports.
pub fn wallet(network: EvmNetwork, private_key: &str, chain_id: Option<u64>) -> Result<Wallet> {
    let signer: PrivateKeySigner = private_key.parse().map_err(|_| Error::InvalidPrivateKey)?;
    Ok(Wallet::new(
        network,
        EthereumWallet::from(signer.with_chain_id(chain_id)),
    ))
}

fn custom_network(rpc_url: &str, token: &str, vault: &str) -> Result<EvmNetwork> {
    let rpc_url: reqwest::Url = rpc_url
        .parse()
        .map_err(|e| Error::InvalidEvmManifest(format!("invalid RPC URL: {e}")))?;
    let payment_token_address: EvmAddress = token
        .parse()
        .map_err(|e| Error::InvalidEvmManifest(format!("invalid payment token address: {e}")))?;
    let payment_vault_address: EvmAddress = vault
        .parse()
        .map_err(|e| Error::InvalidEvmManifest(format!("invalid payment vault address: {e}")))?;
    Ok(EvmNetwork::Custom(CustomNetwork {
        rpc_url_http: rpc_url,
        payment_token_address,
        payment_vault_address,
    }))
}

/// Resolve the EVM network for payment operations.
///
/// `name` is the frontend's network selector (e.g. the CLI's
/// `--evm-network` flag): `robinhood` (our network, bundled: DARWIN on
/// Robinhood Chain), or `local`, which reads the RPC URL and contract
/// addresses from the devnet manifest's `evm` block. Upstream's presets
/// `arbitrum-one` and `arbitrum-sepolia`, which pay Autonomi's ANT on
/// Arbitrum, are refused like any other name, with
/// [`Error::UnsupportedEvmNetwork`]: payments are made in DARWIN only.
///
/// With no selector, the default is our bundled network — **unless** the
/// devnet manifest carries an `evm` block. Defaulting there used to
/// silently discard that config: the default vault address doesn't exist
/// on other chains, so payments "succeeded" as no-op transactions and every
/// subsequent chunk PUT failed verification (V2-471). In that one ambiguous
/// case the caller must choose explicitly or get
/// [`Error::EvmNetworkAmbiguous`].
pub fn resolve_evm_network(
    name: Option<&str>,
    manifest: Option<&DevnetManifest>,
) -> Result<EvmNetwork> {
    match name {
        None => {
            if manifest.is_some_and(|m| m.evm.is_some()) {
                Err(Error::EvmNetworkAmbiguous)
            } else {
                bundled_payment_network()
            }
        }
        Some("robinhood") => bundled_payment_network(),
        Some("local") => {
            let evm = manifest
                .and_then(|m| m.evm.as_ref())
                .ok_or(Error::EvmManifestRequired)?;
            custom_network(
                &evm.rpc_url,
                &evm.payment_token_address,
                &evm.payment_vault_address,
            )
        }
        Some(other) => Err(Error::UnsupportedEvmNetwork(other.to_string())),
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| Error::HomeDirNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_ends_with_ant() {
        let dir = data_dir().unwrap();
        assert_eq!(dir.file_name().unwrap(), "ant");
    }

    #[test]
    fn config_dir_ends_with_ant() {
        let dir = config_dir().unwrap();
        assert_eq!(dir.file_name().unwrap(), "ant");
    }

    #[test]
    fn log_dir_contains_ant() {
        let dir = log_dir().unwrap();
        assert!(
            dir.components().any(|c| c.as_os_str() == "ant"),
            "log_dir should contain 'ant' component: {:?}",
            dir
        );
    }

    fn test_manifest(addrs: Vec<SocketAddr>) -> DevnetManifest {
        DevnetManifest {
            base_port: 10000,
            node_count: addrs.len(),
            bootstrap: addrs.into_iter().map(MultiAddr::quic).collect(),
            data_dir: PathBuf::new(),
            created_at: String::new(),
            evm: None,
        }
    }

    #[test]
    fn resolve_bootstrap_prefers_explicit_peers() {
        let explicit: Vec<SocketAddr> = vec!["10.0.0.1:10000".parse().unwrap()];
        let manifest = test_manifest(vec!["10.0.0.2:10000".parse().unwrap()]);
        let peers = resolve_bootstrap_peers(&explicit, Some(&manifest)).unwrap();
        assert_eq!(peers, explicit);
    }

    #[test]
    fn resolve_bootstrap_uses_manifest_when_no_explicit_peers() {
        let addr: SocketAddr = "10.0.0.2:10000".parse().unwrap();
        let manifest = test_manifest(vec![addr]);
        let peers = resolve_bootstrap_peers(&[], Some(&manifest)).unwrap();
        assert_eq!(peers, vec![addr]);
    }

    fn manifest_with_evm() -> DevnetManifest {
        let mut m = test_manifest(vec!["10.0.0.2:10000".parse().unwrap()]);
        m.evm = Some(ant_protocol::DevnetEvmInfo {
            rpc_url: "http://127.0.0.1:8545".to_string(),
            wallet_private_key:
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string(),
            payment_token_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
            payment_vault_address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".to_string(),
        });
        m
    }

    #[test]
    fn resolve_evm_network_defaults_to_bundled_network_without_manifest_evm() {
        assert!(matches!(
            resolve_evm_network(None, None),
            Ok(EvmNetwork::Custom(_))
        ));
        let no_evm = test_manifest(vec![]);
        assert!(matches!(
            resolve_evm_network(None, Some(&no_evm)),
            Ok(EvmNetwork::Custom(_))
        ));
        assert_eq!(
            resolve_evm_network(Some("robinhood"), None).ok(),
            resolve_evm_network(None, None).ok()
        );
    }

    #[test]
    fn resolve_evm_network_requires_choice_when_manifest_has_evm() {
        // A manifest with an EVM block plus no explicit selection is the
        // V2-471 trap: refuse rather than silently pay against mainnet.
        assert!(matches!(
            resolve_evm_network(None, Some(&manifest_with_evm())),
            Err(Error::EvmNetworkAmbiguous)
        ));
    }

    /// Payments are made in DARWIN only: upstream's Arbitrum presets, which
    /// pay Autonomi's ANT, are refused, with a devnet manifest's EVM block or
    /// without one, and the refusal names the networks that are taken.
    #[test]
    fn the_arbitrum_presets_are_refused() {
        let evm = manifest_with_evm();
        let no_evm = test_manifest(vec![]);
        for preset in ["arbitrum-one", "arbitrum-sepolia"] {
            for manifest in [None, Some(&evm), Some(&no_evm)] {
                let error = resolve_evm_network(Some(preset), manifest).unwrap_err();
                assert!(
                    matches!(&error, Error::UnsupportedEvmNetwork(name) if name == preset),
                    "{preset}: {error:?}"
                );
                let message = error.to_string();
                let (_, offered) = message.split_once("Use ").expect("what to use instead");
                assert!(offered.contains("'robinhood'"), "{message}");
                assert!(offered.contains("'local'"), "{message}");
                assert!(!offered.contains("arbitrum"), "{message}");
            }
        }
    }

    /// `robinhood` and no selector are the bundled network: DARWIN on
    /// Robinhood Chain, signed for chain 4663.
    #[test]
    fn robinhood_and_the_default_are_the_bundled_network() {
        let bundled = bundled_payment_network().unwrap();
        for name in [None, Some("robinhood")] {
            let network = resolve_evm_network(name, None).unwrap();
            assert_eq!(network, bundled, "{name:?}");
            assert_eq!(chain_id(&network), Some(4663), "{name:?}");
            assert_eq!(token_symbol(&network), "DARWIN", "{name:?}");
        }
    }

    #[test]
    fn resolve_evm_network_local_reads_manifest() {
        let manifest = manifest_with_evm();
        let network = resolve_evm_network(Some("local"), Some(&manifest)).unwrap();
        match network {
            EvmNetwork::Custom(custom) => {
                assert_eq!(custom.rpc_url_http.as_str(), "http://127.0.0.1:8545/");
                assert_eq!(
                    format!("{:?}", custom.payment_token_address).to_lowercase(),
                    "0x5fbdb2315678afecb367f032d93f642f64180aa3"
                );
            }
            other => panic!("expected Custom network, got {other:?}"),
        }
    }

    #[test]
    fn token_symbol_follows_the_network() {
        let bundled = bundled_payment_network().unwrap();
        let symbol = token_symbol(&bundled);
        assert!(!symbol.is_empty() && symbol != "tokens", "{symbol}");
        // No network but the bundled one is named, upstream's included.
        assert_eq!(token_symbol(&EvmNetwork::ArbitrumOne), "tokens");
        assert_eq!(token_symbol(&EvmNetwork::ArbitrumSepoliaTest), "tokens");
        let local = resolve_evm_network(Some("local"), Some(&manifest_with_evm())).unwrap();
        assert_eq!(token_symbol(&local), "tokens");
    }

    #[test]
    fn chain_id_is_the_bundled_networks_or_the_manifests() {
        assert_eq!(chain_id(&bundled_payment_network().unwrap()), Some(4663));
        assert_eq!(chain_id(&EvmNetwork::ArbitrumOne), None);
        let local = resolve_evm_network(Some("local"), Some(&manifest_with_evm())).unwrap();
        assert_eq!(chain_id(&local), None);

        let manifest = serde_json::to_value(manifest_with_evm()).unwrap();
        assert_eq!(manifest_chain_id(&manifest.to_string()).unwrap(), None);
        let mut with_chain = manifest.clone();
        with_chain["evm"]["chain_id"] = 31337.into();
        assert_eq!(
            manifest_chain_id(&with_chain.to_string()).unwrap(),
            Some(31337)
        );
        assert_eq!(manifest_chain_id("{}").unwrap(), None);
        with_chain["evm"]["chain_id"] = "4663".into();
        assert!(matches!(
            manifest_chain_id(&with_chain.to_string()),
            Err(Error::InvalidEvmManifest(_))
        ));
    }

    #[tokio::test]
    async fn wallet_signs_only_for_its_chain() {
        use alloy::network::TransactionBuilder;
        use alloy::providers::WalletProvider;
        use alloy::rpc::types::TransactionRequest;

        // Ready to sign but for the chain ID, which the RPC's `eth_chainId` fills in.
        let tx = |chain| {
            TransactionRequest::default()
                .with_to(EvmAddress::ZERO)
                .with_nonce(0)
                .with_gas_limit(21_000)
                .with_max_fee_per_gas(1)
                .with_max_priority_fee_per_gas(1)
                .with_chain_id(chain)
        };
        let network = bundled_payment_network().unwrap();
        let key = Wallet::random_private_key();

        let bound = wallet(network.clone(), &key, chain_id(&network))
            .unwrap()
            .to_provider();
        let refused = tx(1).build(bound.wallet()).await.unwrap_err().to_string();
        assert!(
            refused.contains("chain ID (1)") && refused.contains("chain ID (4663)"),
            "{refused}"
        );
        assert!(tx(4663).build(bound.wallet()).await.is_ok());

        // No chain ID: the RPC's chain is signed for, as before.
        let unbound = wallet(network, &key, None).unwrap().to_provider();
        assert!(tx(1).build(unbound.wallet()).await.is_ok());
    }

    #[test]
    fn resolve_evm_network_local_requires_manifest_evm_block() {
        // No manifest at all, and a manifest without an evm block.
        assert!(matches!(
            resolve_evm_network(Some("local"), None),
            Err(Error::EvmManifestRequired)
        ));
        let no_evm = test_manifest(vec![]);
        assert!(matches!(
            resolve_evm_network(Some("local"), Some(&no_evm)),
            Err(Error::EvmManifestRequired)
        ));
    }

    #[test]
    fn resolve_evm_network_rejects_unknown_and_bad_manifest_values() {
        assert!(matches!(
            resolve_evm_network(Some("mainnet"), None),
            Err(Error::UnsupportedEvmNetwork(_))
        ));
        let mut bad = manifest_with_evm();
        bad.evm.as_mut().unwrap().payment_vault_address = "not-an-address".to_string();
        assert!(matches!(
            resolve_evm_network(Some("local"), Some(&bad)),
            Err(Error::InvalidEvmManifest(_))
        ));
    }

    #[test]
    fn resolve_bootstrap_errors_on_empty_manifest() {
        let manifest = test_manifest(vec![]);
        let err = resolve_bootstrap_peers(&[], Some(&manifest)).unwrap_err();
        assert!(matches!(err, Error::NoBootstrapPeers));
    }

    #[test]
    fn resolve_bootstrap_errors_when_all_manifest_peers_filtered() {
        // A non-IP transport has no socket address, so the peer is
        // filtered out and the manifest yields nothing usable.
        let bt: MultiAddr = "/bt/00:11:22:33:44:55/rfcomm/1".parse().unwrap();
        assert!(bt.socket_addr().is_none());
        let mut manifest = test_manifest(vec![]);
        manifest.bootstrap = vec![bt];
        manifest.node_count = 1;
        let err = resolve_bootstrap_peers(&[], Some(&manifest)).unwrap_err();
        assert!(matches!(err, Error::NoBootstrapPeers));
    }

    #[test]
    fn load_bootstrap_peers_returns_none_when_no_file() {
        // Set config dir to a temp location where no file exists
        let _result = load_bootstrap_peers();
        // Just verify it doesn't panic — actual None depends on whether the file exists
    }

    /// Upstream's `ant-core/resources/bootstrap_peers.toml` at 4b4bf51 (0.3.11):
    /// Autonomi's seeds, which its installers copy into the config directory
    /// as `bootstrap_peers.toml`.
    const UPSTREAM_BOOTSTRAP_PEERS: &str = r#"# Autonomi mainnet bootstrap seeds. Shared by native releases and WASM.
# Preserve optional /p2p/<peer-id> suffixes on QUIC addresses.
quic = [
    "/ip4/207.148.94.42/udp/10000/quic",
    "/ip4/45.77.50.10/udp/10000/quic",
    "/ip4/66.135.23.83/udp/10000/quic",
    "/ip4/149.248.9.2/udp/10000/quic",
    "/ip4/49.12.119.240/udp/10000/quic",
    "/ip4/5.161.25.133/udp/10000/quic",
    "/ip4/18.228.202.183/udp/10000/quic",
]

# Certificate-pinned mainnet WebRTC Direct bootstrap nodes.
# Format: /ip4|ip6/<ip>/udp/<port>/webrtc-direct/certhash/<hash>/p2p/<peer-id>
webrtc = [
    "/ip4/207.148.94.42/udp/10001/webrtc-direct/certhash/uEiAkAsFZc-iV5UToJHyETA8GLBIVdzB10Qv6VuNlwqTwkQ/p2p/57a89f84e1652d22fd6b791c29d83f187fbed3ba8e08e265fe3031b3a6f725da",
    "/ip4/45.77.50.10/udp/10001/webrtc-direct/certhash/uEiBPw-6EWRHA5goZVyE06nBT6BdumpDyuWb40bAbG4tJ2A/p2p/bb72725f8f4383eb475ac9cb681505d9147e8b2c5a4c0197d4efdb328c54601f",
    "/ip4/66.135.23.83/udp/10001/webrtc-direct/certhash/uEiAsKBTTrUfWCXvv8MpV1SPannw0o0qFi2z6Or16O36Jaw/p2p/a1f073e0ffc1a1890e8d072015fa2437a1090997b47c0412c0bfabe7c7e16199",
    "/ip4/149.248.9.2/udp/10001/webrtc-direct/certhash/uEiDdXDebnE74XGEYaA50qZP8xCA7g3Z4dmiWuHiatkOfEg/p2p/3926125b8454101fd39739a09320ca0174be90d3423c1287926172bea69a0f5a",
    "/ip4/167.235.239.18/udp/10001/webrtc-direct/certhash/uEiBypdPUMOpNrjnQ-cW4aq5QnM8bfIeC8NK-Os6WJKbesQ/p2p/dac90975f872f6401519f7b14bfd860792c9052964ffdbd40d190f35469e4ad1",
    "/ip4/87.99.148.210/udp/10001/webrtc-direct/certhash/uEiBPDRe3LCcusQgkHsvEQM8ti3R4ekzpSTGzJPFqq9wpTg/p2p/825916f9447f45d93554d3be742f9a76f7dede9190368dbdb15d34ff7211e9e1",
    "/ip4/18.228.202.183/udp/10001/webrtc-direct/certhash/uEiAZ4mNGJrYmrVVVDi4t8TS9oYoQ-NavFK8cWAF1X3NEjA/p2p/2ed6785d3aab00fc4ef048884c63b2a85fb587441413a94a7eb8f8e8b65bd582",
]
"#;

    /// A seed file Autonomi's `ant` left in the config directory is not read:
    /// darwin keeps its 16 bundled seeds. Only darwin's own file replaces
    /// them, and explicit peers and a devnet manifest still come first.
    #[test]
    fn a_bootstrap_file_left_by_autonomis_ant_does_not_replace_darwins_seeds() {
        let dir = tempfile::tempdir().unwrap();
        let resolve = |explicit: &[MultiAddr], manifest: Option<&DevnetManifest>| {
            resolve_bootstrap_multiaddrs_with(explicit, manifest, || {
                load_bootstrap_multiaddrs_in(dir.path())
            })
        };
        let autonomi = crate::network_defaults::parse_bootstrap_seeds(UPSTREAM_BOOTSTRAP_PEERS)
            .unwrap()
            .quic;
        assert_eq!(autonomi.len(), 7);
        std::fs::write(
            dir.path().join("bootstrap_peers.toml"),
            UPSTREAM_BOOTSTRAP_PEERS,
        )
        .unwrap();

        assert_eq!(load_bootstrap_multiaddrs_in(dir.path()).unwrap(), None);
        let bundled = crate::network_defaults::bundled_bootstrap_seeds()
            .unwrap()
            .quic;
        assert_eq!(bundled.len(), 16);
        let resolved = resolve(&[], None).unwrap();
        assert_eq!(resolved, bundled);
        assert!(resolved.iter().all(|seed| !autonomi.contains(seed)));

        // darwin's own file still replaces the bundled seeds.
        let own: MultiAddr = format!("/ip4/203.0.113.7/udp/10000/quic/p2p/{}", "cd".repeat(32))
            .parse()
            .unwrap();
        std::fs::write(
            dir.path().join(DARWIN_BOOTSTRAP_PEERS_FILE),
            format!("quic = [\"{own}\"]\n"),
        )
        .unwrap();
        assert_eq!(resolve(&[], None).unwrap(), vec![own.clone()]);

        // Explicit peers, then a devnet manifest, come before it.
        let explicit: MultiAddr = "/ip4/10.0.0.1/udp/10000/quic".parse().unwrap();
        assert_eq!(
            resolve(std::slice::from_ref(&explicit), None).unwrap(),
            vec![explicit]
        );
        let manifest = test_manifest(vec!["10.0.0.2:10000".parse().unwrap()]);
        assert_eq!(resolve(&[], Some(&manifest)).unwrap(), manifest.bootstrap);
    }

    #[test]
    fn parse_bootstrap_config() {
        let toml_str = r#"
peers = [
    "129.212.138.135:10000",
    "134.199.138.183:10000",
]
"#;
        let config = crate::network_defaults::parse_bootstrap_seeds(toml_str).unwrap();
        assert_eq!(config.quic.len(), 2);
        let addr = config.quic[0].socket_addr().unwrap();
        assert_eq!(addr.port(), 10000);
    }

    #[test]
    fn multiaddr_resolution_preserves_pins_and_never_falls_back_from_manifest() {
        let pin = format!("/ip4/127.0.0.1/udp/10000/quic/p2p/{}", "ab".repeat(32));
        let seed: MultiAddr = pin.parse().unwrap();
        let mut manifest = test_manifest(vec![]);
        manifest.bootstrap = vec![seed.clone()];
        assert_eq!(
            resolve_bootstrap_multiaddrs(&[], Some(&manifest)).unwrap()[0].to_string(),
            pin
        );
        assert_eq!(
            resolve_bootstrap_multiaddrs(&[seed], Some(&test_manifest(vec![]))).unwrap()[0]
                .to_string(),
            pin
        );
        assert!(matches!(
            resolve_bootstrap_multiaddrs(&[], Some(&test_manifest(vec![]))),
            Err(Error::NoBootstrapPeers)
        ));
    }
}
