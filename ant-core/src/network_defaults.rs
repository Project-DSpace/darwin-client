//! Release-bundled bootstrap multiaddresses and portable payment defaults.

use ant_protocol::transport::MultiAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::browser::{
    parse_webrtc_direct_multiaddr, validate_browser_payment_network, BrowserPaymentNetwork,
};

const BOOTSTRAP: &str = include_str!("../resources/bootstrap_peers.toml");
/// The payment chain native builds use by default (`--evm-network robinhood`).
const PAYMENT_NETWORK: &str = include_str!("../resources/payment_network.toml");

/// Validated bootstrap addresses, separated by transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapSeeds {
    /// Native QUIC multiaddresses, including any supplied peer identity.
    pub quic: Vec<MultiAddr>,
    /// Complete certificate-pinned WebRTC Direct multiaddresses.
    pub webrtc: Vec<String>,
}

/// A configuration error detected before opening any network connection.
#[derive(Debug, thiserror::Error)]
#[error("invalid bootstrap configuration: {0}")]
pub struct NetworkDefaultsError(String);

/// Parse a QUIC multiaddress, accepting legacy socket addresses for migration.
pub fn parse_quic_seed(value: &str) -> Result<MultiAddr, NetworkDefaultsError> {
    let address = if let Ok(socket) = value.parse::<std::net::SocketAddr>() {
        MultiAddr::quic(socket)
    } else {
        value
            .parse::<MultiAddr>()
            .map_err(|e| NetworkDefaultsError(e.to_string()))?
    };
    if !address.is_quic() || address.socket_addr().is_none_or(|a| a.port() == 0) {
        return Err(NetworkDefaultsError(
            "expected a QUIC multiaddress with a nonzero port".into(),
        ));
    }
    Ok(address)
}

/// Read both transport lists. Legacy `peers` is an alias for `quic`.
pub fn parse_bootstrap_seeds(text: &str) -> Result<BootstrapSeeds, NetworkDefaultsError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        #[serde(default, alias = "peers")]
        quic: Vec<String>,
        #[serde(default)]
        webrtc: Vec<String>,
    }
    let input: Input = toml::from_str(text).map_err(|e| NetworkDefaultsError(e.to_string()))?;
    let mut seen = HashSet::new();
    let mut quic = Vec::new();
    for value in input.quic {
        let address = parse_quic_seed(&value)?;
        if !seen.insert(address.to_string()) {
            return Err(NetworkDefaultsError("duplicate QUIC seed".into()));
        }
        quic.push(address);
    }
    let mut webrtc = Vec::new();
    for value in input.webrtc {
        let address = parse_webrtc_direct_multiaddr(&value)
            .map_err(|e| NetworkDefaultsError(e.to_string()))?
            .multiaddr;
        if !seen.insert(address.clone()) {
            return Err(NetworkDefaultsError("duplicate WebRTC seed".into()));
        }
        webrtc.push(address);
    }
    Ok(BootstrapSeeds { quic, webrtc })
}

/// The same resource shipped by native release archives.
pub fn bundled_bootstrap_seeds() -> Result<BootstrapSeeds, NetworkDefaultsError> {
    parse_bootstrap_seeds(BOOTSTRAP)
}

/// Browser-only projection of the trusted mainnet configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserNetworkDefaults {
    pub id: String,
    pub seeds: Vec<String>,
    pub payment: BrowserPaymentNetwork,
    pub rpc_url: String,
}

/// Return defaults without connecting: the bundled WebRTC seeds and the
/// bundled payment network (Robinhood Chain, DARWIN), the same identity the
/// native client pays on by default.
pub fn browser_mainnet_defaults() -> Result<BrowserNetworkDefaults, NetworkDefaultsError> {
    #[derive(Deserialize)]
    struct Payment {
        chain_id: u64,
        rpc_url: String,
        payment_token_address: String,
        payment_vault_address: String,
    }
    let config: Payment =
        toml::from_str(PAYMENT_NETWORK).map_err(|e| NetworkDefaultsError(e.to_string()))?;
    let payment = validate_browser_payment_network(BrowserPaymentNetwork {
        chain_id: config.chain_id,
        payment_token_address: config.payment_token_address,
        payment_vault_address: config.payment_vault_address,
    })
    .map_err(|e| NetworkDefaultsError(e.to_string()))?;
    Ok(BrowserNetworkDefaults {
        id: "mainnet".into(),
        seeds: bundled_bootstrap_seeds()?.webrtc,
        payment,
        rpc_url: config.rpc_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_defaults_share_evm_identity_and_exclude_quic() {
        let seeds = bundled_bootstrap_seeds().unwrap();
        assert!(!seeds.quic.is_empty());
        assert!(!seeds.webrtc.is_empty());
        let browser = browser_mainnet_defaults().unwrap();
        assert_eq!(browser.seeds, seeds.webrtc);
        assert!(browser.seeds.iter().all(|s| s.contains("/webrtc-direct/")));
        // Robinhood Chain and the DARWIN vault, as the native client's default.
        assert_eq!(browser.payment.chain_id, 4663);
        assert_eq!(
            browser.payment.payment_token_address,
            "0x511f76a3de41f000ec11ea4fd212fb3587c6cef3"
        );
        assert_eq!(
            browser.payment.payment_vault_address,
            "0xe0f627986c0438de0e314b644f3c8aa21d3f4f6b"
        );
        assert!(browser.rpc_url.starts_with("https://"));
    }

    #[test]
    fn bundled_quic_seeds_are_both_nodes_of_every_server_with_their_peer_ids() {
        let seeds = bundled_bootstrap_seeds().unwrap();
        assert_eq!(seeds.quic.len(), 16);
        assert_eq!(seeds.webrtc.len(), 16);
        // Each node's browser address, by IP and port, and its peer ID.
        let browser: std::collections::HashMap<_, _> = seeds
            .webrtc
            .iter()
            .map(|seed| {
                let address: MultiAddr = seed.parse().unwrap();
                let id = *address.peer_id().unwrap();
                ((address.ip().unwrap(), address.port().unwrap()), id)
            })
            .collect();
        let mut ids = HashSet::new();
        let mut servers = HashSet::new();
        for seed in &seeds.quic {
            let id = seed
                .peer_id()
                .unwrap_or_else(|| panic!("{seed} has no peer ID"));
            let socket = seed.socket_addr().unwrap();
            assert!(matches!(socket.port(), 10000 | 10001), "{seed}");
            // The same node serves QUIC 1000 below its browser port.
            assert_eq!(
                browser.get(&(socket.ip(), socket.port() + 1000)),
                Some(id),
                "{seed}"
            );
            assert!(ids.insert(*id), "{seed} repeats a peer ID");
            servers.insert(socket.ip());
        }
        assert_eq!(servers.len(), 8);
        // Seeds are dialled in order, a few at a time: every server's first
        // node comes before any server's second, so the first dials spread.
        let (first, second) = seeds.quic.split_at(8);
        let ips = |seeds: &[MultiAddr], port| {
            seeds
                .iter()
                .map(|seed| {
                    let socket = seed.socket_addr().unwrap();
                    assert_eq!(socket.port(), port, "{seed}");
                    socket.ip()
                })
                .collect::<HashSet<_>>()
        };
        assert_eq!(ips(first, 10000), servers);
        assert_eq!(ips(second, 10001), servers);
    }

    #[test]
    fn preserves_quic_peer_pins_and_legacy_sockets() {
        let pin = format!("/ip6/::1/udp/10000/quic/p2p/{}", "ab".repeat(32));
        let seeds = parse_bootstrap_seeds(&format!("quic = [\"{pin}\"]\nwebrtc = []")).unwrap();
        assert_eq!(seeds.quic[0].to_string(), pin);
        let legacy = parse_bootstrap_seeds("peers = [\"127.0.0.1:10000\"]").unwrap();
        assert_eq!(legacy.quic[0].to_string(), "/ip4/127.0.0.1/udp/10000/quic");
    }

    #[test]
    fn keeps_valid_webrtc_seeds_separate_and_rejects_duplicates() {
        use base64::Engine;
        let mut hash = vec![0x12, 0x20];
        hash.extend([0xbb; 32]);
        let cert = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
        let endpoint = format!(
            "/ip4/127.0.0.1/udp/24000/webrtc-direct/certhash/u{cert}/p2p/{}",
            "ab".repeat(32)
        );
        let input =
            format!("quic = [\"/ip4/127.0.0.1/udp/10000/quic\"]\nwebrtc = [\"{endpoint}\"]");
        let parsed = parse_bootstrap_seeds(&input).unwrap();
        assert_eq!(parsed.quic.len(), 1);
        assert_eq!(parsed.webrtc, vec![endpoint.clone()]);
        assert!(
            parse_bootstrap_seeds(&format!("webrtc = [\"{endpoint}\", \"{endpoint}\"]")).is_err()
        );
        assert!(parse_bootstrap_seeds(&format!("quic = [\"{endpoint}\"]")).is_err());
    }

    #[test]
    fn rejects_wrong_transport_duplicates_and_invalid_seeds() {
        for input in [
            "quic = [\"/ip4/127.0.0.1/tcp/10000\"]",
            "quic = [\"127.0.0.1:0\"]",
            "quic = [\"invalid\"]",
            "quic = [\"127.0.0.1:10000\", \"/ip4/127.0.0.1/udp/10000/quic\"]",
            "webrtc = [\"/ip4/127.0.0.1/udp/10000/quic\"]",
            "webrtc = [\"127.0.0.1:10000\"]",
        ] {
            assert!(parse_bootstrap_seeds(input).is_err(), "{input}");
        }
    }
}
