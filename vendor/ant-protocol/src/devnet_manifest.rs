//! Devnet manifest — on-disk handoff between a running devnet and
//! clients that want to connect to it.
//!
//! The manifest is a JSON document that the devnet writes when it
//! starts (bootstrap peers, data dir, optional EVM info) and that a
//! client (`ant-cli`, `LocalDevnet`, an SDK wrapper) reads to discover
//! the network. Both sides need the same type, and neither side needs
//! to pull in the node runtime to read or write it — so it lives here.

use saorsa_core::MultiAddr;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Devnet manifest for client discovery.
///
/// Written by the devnet launcher (see `ant_node::devnet::Devnet`) and
/// read by clients via the `--devnet-manifest <path>` CLI flag or the
/// `LocalDevnet::write_manifest` helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevnetManifest {
    /// Base port for nodes.
    pub base_port: u16,
    /// Node count.
    pub node_count: usize,
    /// Bootstrap addresses.
    pub bootstrap: Vec<MultiAddr>,
    /// Data directory.
    pub data_dir: PathBuf,
    /// Creation time (RFC 3339 or Unix seconds; the launcher picks the
    /// format — clients treat this as opaque text).
    pub created_at: String,
    /// EVM configuration (present when EVM payment enforcement is enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm: Option<DevnetEvmInfo>,
}

/// EVM configuration info included in the devnet manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevnetEvmInfo {
    /// Anvil RPC URL.
    pub rpc_url: String,
    /// Funded wallet private key (hex-encoded with 0x prefix).
    pub wallet_private_key: String,
    /// Payment token contract address.
    pub payment_token_address: String,
    /// Unified payment vault contract address (handles both single-node and merkle payments).
    pub payment_vault_address: String,
}
