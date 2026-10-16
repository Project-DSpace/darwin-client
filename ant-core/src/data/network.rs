//! Network layer wrapping ant-node's P2P node.
//!
//! Provides peer discovery, message sending, and DHT operations
//! for the client library.

#[cfg(feature = "native")]
use crate::data::error::Error;
use crate::data::error::Result;
use ant_protocol::transport::{DHTNode, MultiAddr, PeerId, WitnessedCloseGroup};
#[cfg(feature = "native")]
use ant_protocol::{
    transport::{CoreNodeConfig, IPDiversityConfig, NodeMode, P2PNode},
    MAX_WIRE_MESSAGE_SIZE,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "native")]
use std::net::SocketAddr;
#[cfg(feature = "native")]
use std::sync::Arc;

/// Mirror of saorsa-core's private `AUTO_REBOOTSTRAP_THRESHOLD`
/// (dht_network_manager.rs): the routing-table size below which the DHT
/// auto-re-bootstraps. saorsa-core PR #153 makes the real const public;
/// once a release carries it, consume that instead of this mirror.
pub const REBOOTSTRAP_THRESHOLD: usize = 3;

/// Live network-participation snapshot.
///
/// One implementation of the write-readiness formula for every embedded-client
/// consumer (antd, ant-gui, ant-ffi, ant-tui) — see [`Network::health`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkHealth {
    /// Best-effort write-path floor:
    /// `max(routing_table_size, connected_peers) >= rebootstrap_threshold`.
    pub write_ready: bool,
    /// Identity-verified peer connections currently held by the node.
    pub connected_peers: u32,
    /// Entries in the DHT routing table.
    pub routing_table_size: u32,
    /// Routing-table size below which the DHT auto-re-bootstraps.
    pub rebootstrap_threshold: u32,
}

impl NetworkHealth {
    /// Build a snapshot from raw peer counts.
    ///
    /// `write_ready` is keyed on `max(routing_table_size, connected_peers)`:
    /// in client mode the DHT routing table can sit below the re-bootstrap
    /// threshold while plenty of live connections exist and stores succeed
    /// (observed on a LAN devnet: rt=2, connected=10, paid upload fine), so
    /// the routing table alone would under-report; the connected count alone
    /// misses the inverse case (~1 reachable peer, rt=0, stores failing).
    /// Neither signal guarantees a store will fully succeed (stores proceed
    /// with as little as one reachable node), but when both are below the
    /// threshold the node is known-degraded.
    #[must_use]
    pub fn from_counts(connected_peers: usize, routing_table_size: usize) -> Self {
        Self {
            write_ready: routing_table_size.max(connected_peers) >= REBOOTSTRAP_THRESHOLD,
            connected_peers: connected_peers.try_into().unwrap_or(u32::MAX),
            routing_table_size: routing_table_size.try_into().unwrap_or(u32::MAX),
            rebootstrap_threshold: REBOOTSTRAP_THRESHOLD as u32,
        }
    }
}

/// Read-only DHT context captured for one diagnostics-enabled closest-peer
/// selection. None of these fields influence selection or dialing.
#[cfg(feature = "native")]
pub(crate) struct ClosestPeerDiagnostics {
    pub peer_id: PeerId,
    pub addresses: Vec<MultiAddr>,
    pub address_types: Vec<String>,
    /// This process's monotonic age since its last successful DHT interaction.
    pub local_last_seen_age_ms: Option<u64>,
    /// Publisher-clock-derived age of the latest address-set publication.
    pub publisher_address_set_age_ms: Option<u64>,
    pub publisher_address_set_unix_ns: Option<u64>,
}

/// Network abstraction for the Autonomi client.
///
/// Wraps a `P2PNode` providing high-level operations for
/// peer discovery and message routing.
#[derive(Clone)]
pub struct Network {
    #[cfg(feature = "native")]
    node: Arc<P2PNode>,
    /// The bootstrap addresses reads also ask, as configured. Only those
    /// carrying a peer ID are used: see [`Network::bootstrap_peers_near`].
    #[cfg(feature = "native")]
    bootstrap: Vec<MultiAddr>,
    #[cfg(not(feature = "native"))]
    backend: std::rc::Rc<dyn BrowserNetwork>,
}

/// Peer identities and the addresses that can reach them.
pub type PeerAddresses = Vec<(PeerId, Vec<MultiAddr>)>;

/// The most bootstrap peers a read asks: the nine nearest the address read.
///
/// Nine is the nodes' storage retention width: the close group
/// ([`ant_protocol::CLOSE_GROUP_SIZE`], seven) plus the storage admission
/// margin of two (darwin-node's `storage_admission_width`, in
/// `src/replication/config.rs`). A node keeps and serves a record it admitted
/// while it was among the nine nodes nearest the record. A bootstrap peer that
/// is among the nine nodes nearest an address out of the whole network is also
/// among the nine nearest out of the bootstrap peers, so asking the nine
/// bootstrap peers nearest the address asks every bootstrap peer that can hold
/// the record.
pub(crate) const MAX_BOOTSTRAP_READ_PEERS: usize = ant_protocol::CLOSE_GROUP_SIZE + 2;

/// The bootstrap peers among `seeds` that a read of `target` asks: the
/// [`MAX_BOOTSTRAP_READ_PEERS`] nearest to it by XOR distance, or all of them
/// when there are fewer, nearest first, each with all of its addresses. Only
/// addresses that carry a peer ID count, and the local peer is left out.
pub(crate) fn bootstrap_read_peers(
    seeds: &[MultiAddr],
    target: &[u8; 32],
    local: &PeerId,
) -> PeerAddresses {
    let mut peers: PeerAddresses = Vec::new();
    // Where each peer is in `peers`.
    let mut index = std::collections::HashMap::<PeerId, usize>::new();
    for seed in seeds {
        let Some(peer) = seed.peer_id() else {
            continue;
        };
        if peer == local {
            continue;
        }
        match index.get(peer).and_then(|&at| peers.get_mut(at)) {
            Some((_, addrs)) => {
                if !addrs.contains(seed) {
                    addrs.push(seed.clone());
                }
            }
            None => {
                index.insert(*peer, peers.len());
                peers.push((*peer, vec![seed.clone()]));
            }
        }
    }
    peers.sort_by_key(|(peer, _)| ant_protocol::transport::xor_distance(peer.as_bytes(), target));
    peers.truncate(MAX_BOOTSTRAP_READ_PEERS);
    peers
}

/// Bounded, latest-value hints for an immutable read in progress. Hints only
/// start authenticated GETs; they never establish closeness, absence or payment
/// authority. The receiver may cancel discovery after verifying content.
#[derive(Clone)]
pub struct ReadProgress {
    target: [u8; 32],
    local: PeerId,
    sender: tokio::sync::watch::Sender<PeerAddresses>,
}

impl ReadProgress {
    pub(crate) fn new(
        target: [u8; 32],
        local: PeerId,
        sender: tokio::sync::watch::Sender<PeerAddresses>,
    ) -> Self {
        Self {
            target,
            local,
            sender,
        }
    }

    /// Offer authenticated discovery hints, retaining only the nearest bounded
    /// set. Sending never waits for a slow read consumer.
    pub fn offer(&self, peers: PeerAddresses) {
        if self.sender.is_closed() {
            return;
        }
        self.sender.send_modify(|current| {
            for peer in peers {
                if peer.0 == self.local || peer.1.is_empty() {
                    continue;
                }
                if let Some(existing) = current.iter_mut().find(|entry| entry.0 == peer.0) {
                    *existing = peer;
                } else {
                    current.push(peer);
                }
            }
            current.sort_by_key(|peer| {
                ant_protocol::transport::xor_distance(peer.0.as_bytes(), &self.target)
            });
            current.truncate(crate::client_engine::read::MAX_GET_FALLBACK_PEERS);
        });
    }
}

/// Browser transport boundary for the shared client. Implementations perform
/// authenticated RPC and discovery; client policy stays in `Client`.
#[cfg(not(feature = "native"))]
pub trait BrowserNetwork {
    /// Local identity used when excluding the client from remote candidates.
    fn peer_id(&self) -> &PeerId;
    /// Closest authenticated peers, ordered by XOR distance.
    fn find_closest_peers<'a>(
        &'a self,
        target: &'a [u8; 32],
        count: usize,
    ) -> futures::future::LocalBoxFuture<'a, Result<PeerAddresses>>;
    /// Read-only discovery may report verified candidates before completing.
    /// Existing adapters remain compatible and supply their final result only.
    fn find_read_peers<'a>(
        &'a self,
        target: &'a [u8; 32],
        count: usize,
        _progress: ReadProgress,
    ) -> futures::future::LocalBoxFuture<'a, Result<PeerAddresses>> {
        self.find_closest_peers(target, count)
    }
    /// Authenticated responder views for witnessed quote admission.
    fn find_witnessed_close_group<'a>(
        &'a self,
        target: &'a [u8; 32],
        count: usize,
        view_count: usize,
    ) -> futures::future::LocalBoxFuture<'a, Result<WitnessedCloseGroup>>;
    /// Known records used as fallback candidates after a lookup failure.
    fn known_peers(&self) -> Vec<DHTNode>;
    /// Authenticated live peers eligible for an opportunistic immutable read.
    /// Adapters without connection telemetry retain discovery-first behavior.
    fn connected_read_peers(&self) -> Vec<PeerId> {
        Vec::new()
    }
    /// Bootstrap addresses that chunk and pointer reads also ask, alongside
    /// discovery: of those carrying a peer ID, the nine nearest the address
    /// read. Adapters without them read through discovery alone.
    fn bootstrap_peers(&self) -> Vec<MultiAddr> {
        Vec::new()
    }
    /// Execute one authenticated request, preserving its request identifier.
    fn request<'a>(
        &'a self,
        peer: &'a PeerId,
        addrs: &'a [MultiAddr],
        request: ant_protocol::ChunkMessage,
        timeout: std::time::Duration,
    ) -> futures::future::LocalBoxFuture<'a, Result<ant_protocol::ChunkMessage>>;
}

impl Network {
    /// Create a new network connection with the given bootstrap peers.
    ///
    /// `allow_loopback` controls the saorsa-transport `local` flag on the
    /// underlying `CoreNodeConfig`. Set it to `true` only for devnet / local
    /// testing. Public Autonomi network peers reject the QUIC handshake
    /// variant produced when `local = true`, so production callers must pass
    /// `false` (this is what `ant-cli` does by default — see
    /// `ant-cli/src/main.rs::create_client_node_raw`, which builds a similar
    /// `CoreNodeConfig` directly, with `ipv6` toggled by the `--ipv4-only`
    /// flag).
    ///
    /// `ipv6` controls whether the node binds a dual-stack IPv6 socket
    /// (`true`) or an IPv4-only socket (`false`). The default for library
    /// callers should be `true` to match the CLI default; set it to `false`
    /// only when running on hosts without a working IPv6 stack, to avoid
    /// advertising unreachable v6 addresses to the DHT.
    ///
    /// # Errors
    ///
    /// Returns an error if the P2P node cannot be created or bootstrapping fails.
    #[cfg(feature = "native")]
    pub async fn new(
        bootstrap_peers: &[SocketAddr],
        allow_loopback: bool,
        ipv6: bool,
    ) -> Result<Self> {
        let seeds: Vec<_> = bootstrap_peers
            .iter()
            .copied()
            .map(MultiAddr::quic)
            .collect();
        Self::new_multiaddrs(&seeds, allow_loopback, ipv6).await
    }

    /// Connect using QUIC multiaddresses, preserving optional peer identity pins.
    /// Chunk and pointer reads also ask the seeds that carry a peer ID, the
    /// nine nearest the address read.
    #[cfg(feature = "native")]
    pub async fn new_multiaddrs(
        bootstrap_peers: &[MultiAddr],
        allow_loopback: bool,
        ipv6: bool,
    ) -> Result<Self> {
        let network = Self::unstarted(bootstrap_peers, allow_loopback, ipv6).await?;
        network
            .node
            .start()
            .await
            .map_err(|e| Error::Network(format!("Failed to start P2P node: {e}")))?;
        Ok(network)
    }

    /// The network [`Network::new_multiaddrs`] starts: a client node that
    /// bootstraps from `bootstrap_peers`, which reads also ask.
    #[cfg(feature = "native")]
    async fn unstarted(
        bootstrap_peers: &[MultiAddr],
        allow_loopback: bool,
        ipv6: bool,
    ) -> Result<Self> {
        let seeds = bootstrap_peers
            .iter()
            .map(|addr| crate::network_defaults::parse_quic_seed(&addr.to_string()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Network(e.to_string()))?;
        let mut core_config = CoreNodeConfig::builder()
            .port(0)
            .ipv6(ipv6)
            .local(allow_loopback)
            .mode(NodeMode::Client)
            .max_message_size(MAX_WIRE_MESSAGE_SIZE)
            .build()
            .map_err(|e| Error::Network(format!("Failed to create core config: {e}")))?;

        // Clients never enforce IP-diversity limits: they don't host data and
        // their routing table exists only to find peers, not to be defended
        // against Sybil clustering. Strict per-IP / per-subnet caps would
        // silently drop legitimate testnet peers that share an IP or /24.
        core_config.diversity_config = Some(IPDiversityConfig::permissive());

        core_config.bootstrap_peers = seeds.clone();

        let node = P2PNode::new(core_config)
            .await
            .map_err(|e| Error::Network(format!("Failed to create P2P node: {e}")))?;

        Ok(Self {
            node: Arc::new(node),
            bootstrap: seeds,
        })
    }

    /// Create a network from an existing P2P node. Reads ask no bootstrap
    /// peers unless the client is given some (`Client::with_bootstrap_peers`).
    #[must_use]
    #[cfg(feature = "native")]
    pub fn from_node(node: Arc<P2PNode>) -> Self {
        Self {
            node,
            bootstrap: Vec::new(),
        }
    }

    /// Replace the bootstrap addresses reads also ask.
    #[cfg(feature = "native")]
    pub(crate) fn set_bootstrap_peers(&mut self, seeds: &[MultiAddr]) {
        self.bootstrap = seeds.to_vec();
    }

    /// The bootstrap addresses chunk and pointer reads also ask, as the
    /// network was given them. A read asks the nine nearest the address read
    /// of those that carry a peer ID.
    #[must_use]
    #[cfg(feature = "native")]
    pub fn bootstrap_peers(&self) -> &[MultiAddr] {
        &self.bootstrap
    }

    /// Get a reference to the underlying P2P node.
    #[must_use]
    #[cfg(feature = "native")]
    pub fn node(&self) -> &Arc<P2PNode> {
        &self.node
    }

    /// Get the local peer ID.
    #[must_use]
    #[cfg(feature = "native")]
    pub fn peer_id(&self) -> &PeerId {
        self.node.peer_id()
    }

    /// Find the closest peers to a target address.
    ///
    /// Returns each peer paired with its known network addresses, enabling
    /// callers to pass addresses to `send_and_await_chunk_response` for
    /// faster connection establishment.
    ///
    /// # Errors
    ///
    /// Returns an error if the DHT lookup fails.
    #[cfg(feature = "native")]
    pub async fn find_closest_peers(
        &self,
        target: &[u8; 32],
        count: usize,
    ) -> Result<Vec<(PeerId, Vec<MultiAddr>)>> {
        let local_peer_id = self.node.peer_id();

        // Request one extra to account for filtering out our own peer ID
        // Keep the large transport future behind the adapter boundary. This
        // preserves Send without expanding the entire dial/lookup type through
        // the shared discovery/read race and recursive DataMap resolver.
        let lookup: futures::future::BoxFuture<'_, _> =
            Box::pin(self.node.dht().find_closest_nodes(target, count + 1));
        let closest_nodes = lookup
            .await
            .map_err(|e| Error::Network(format!("DHT closest-nodes lookup failed: {e}")))?;

        Ok(closest_nodes
            .into_iter()
            .filter(|n| n.peer_id != *local_peer_id)
            .take(count)
            .map(|n| {
                let addrs = n.addresses_by_priority();
                (n.peer_id, addrs)
            })
            .collect())
    }

    /// Find the same peers, in the same order, while capturing read-only DHT
    /// context for the explicitly enabled download diagnostics sidecar.
    #[cfg(feature = "native")]
    pub(crate) async fn find_closest_peers_with_diagnostics(
        &self,
        target: &[u8; 32],
        count: usize,
    ) -> Result<Vec<ClosestPeerDiagnostics>> {
        let local_peer_id = self.node.peer_id();
        let lookup: futures::future::BoxFuture<'_, _> =
            Box::pin(self.node.dht().find_closest_nodes(target, count + 1));
        let closest_nodes = lookup
            .await
            .map_err(|e| Error::Network(format!("DHT closest-nodes lookup failed: {e}")))?;
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let now_ns = u64::try_from(now_ns).unwrap_or(u64::MAX);

        let mut result = Vec::with_capacity(count);
        for node in closest_nodes
            .into_iter()
            .filter(|node| node.peer_id != *local_peer_id)
            .take(count)
        {
            let publisher_address_set_unix_ns = node.publisher_address_set_unix_ns();
            // A publisher clock may be ahead of ours. In that case, retain the
            // raw timestamp but do not misreport its age as zero.
            let publisher_address_set_age_ms = publisher_address_set_unix_ns
                .and_then(|published| now_ns.checked_sub(published))
                .map(|age_ns| age_ns / 1_000_000);
            let local_last_seen_age_ms = self
                .node
                .peer_last_seen_elapsed(&node.peer_id)
                .await
                .map(|age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX));
            let address_context = node.address_and_type_labels_by_priority();
            let (addresses, address_types) = address_context
                .into_iter()
                .map(|(address, label)| (address, label.to_string()))
                .unzip();
            result.push(ClosestPeerDiagnostics {
                peer_id: node.peer_id,
                addresses,
                address_types,
                local_last_seen_age_ms,
                publisher_address_set_age_ms,
                publisher_address_set_unix_ns,
            });
        }
        Ok(result)
    }

    /// Find a witnessed close-group transcript for a target address.
    ///
    /// The underlying DHT method returns the initial client K, each responder's
    /// self-inclusive closest-K node view, and enough trusted node records for
    /// callers to apply their own quorum and fallback policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the DHT lookup itself fails. The returned transcript
    /// may still be inconclusive; callers should evaluate it before payment.
    pub async fn find_witnessed_close_group(
        &self,
        target: &[u8; 32],
        count: usize,
    ) -> Result<WitnessedCloseGroup> {
        self.find_witnessed_close_group_with_view_count(target, count, count)
            .await
    }

    /// Find a witnessed close-group transcript with wider responder views.
    ///
    /// `count` is the initial responder set size. `view_count` is the number
    /// of closest nodes each responder view may contribute.
    ///
    /// # Errors
    ///
    /// Returns an error if the DHT lookup itself fails. The returned transcript
    /// may still be inconclusive; callers should evaluate it before payment.
    #[cfg(feature = "native")]
    pub async fn find_witnessed_close_group_with_view_count(
        &self,
        target: &[u8; 32],
        count: usize,
        view_count: usize,
    ) -> Result<WitnessedCloseGroup> {
        self.node
            .dht()
            .find_witnessed_close_group_with_view_count(target, count, view_count)
            .await
            .map_err(|e| Error::Network(format!("DHT witnessed close-group lookup failed: {e}")))
    }

    /// Get all currently connected peers.
    #[cfg(feature = "native")]
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.node.connected_peers().await
    }

    /// Compute the live network-participation snapshot.
    ///
    /// Both node reads are in-memory, so this is cheap enough to call per
    /// request — no caching or background worker needed. See
    /// [`NetworkHealth::from_counts`] for the `write_ready` semantics.
    ///
    /// Do not substitute `is_bootstrapped()` (sticky true — it stays true
    /// through a total outage) or saorsa's `health_check()` (an
    /// over-connection guard, despite the name) for this.
    #[cfg(feature = "native")]
    pub async fn health(&self) -> NetworkHealth {
        let connected_peers = self.node.peer_count().await;
        let routing_table_size = self.node.dht_manager().get_routing_table_size().await;
        NetworkHealth::from_counts(connected_peers, routing_table_size)
    }
}

impl Network {
    /// Construct the same client network facade with a browser transport.
    #[cfg(not(feature = "native"))]
    pub fn from_browser(backend: std::rc::Rc<dyn BrowserNetwork>) -> Self {
        Self { backend }
    }

    /// Local client identity.
    #[cfg(not(feature = "native"))]
    pub fn peer_id(&self) -> &PeerId {
        self.backend.peer_id()
    }

    /// Find closest authenticated peers through the browser adapter.
    #[cfg(not(feature = "native"))]
    pub async fn find_closest_peers(
        &self,
        target: &[u8; 32],
        count: usize,
    ) -> Result<Vec<(PeerId, Vec<MultiAddr>)>> {
        self.backend.find_closest_peers(target, count).await
    }

    /// Collect authenticated close-group responder views.
    #[cfg(not(feature = "native"))]
    pub async fn find_witnessed_close_group_with_view_count(
        &self,
        target: &[u8; 32],
        count: usize,
        view_count: usize,
    ) -> Result<WitnessedCloseGroup> {
        self.backend
            .find_witnessed_close_group(target, count, view_count)
            .await
    }

    /// Currently known peers on the browser session.
    #[cfg(not(feature = "native"))]
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.backend
            .known_peers()
            .into_iter()
            .map(|node| node.peer_id)
            .collect()
    }

    /// Peer records available for fallback retrieval.
    pub async fn known_peers(&self) -> Vec<DHTNode> {
        #[cfg(feature = "native")]
        {
            self.node.dht().routing_table_peers().await
        }
        #[cfg(not(feature = "native"))]
        {
            self.backend.known_peers()
        }
    }

    /// The bootstrap peers a read of `target` also asks, nearest first: the
    /// [`MAX_BOOTSTRAP_READ_PEERS`] nearest it of those whose configured
    /// address carries a peer ID ([`bootstrap_read_peers`]). Native clients
    /// use the addresses they connected through or were given; browser clients
    /// use their seeds, less any whose node the seed policy rejected. Empty
    /// when no bootstrap address carries a peer ID, and reads then use
    /// discovery alone.
    pub(crate) fn bootstrap_peers_near(&self, target: &[u8; 32]) -> PeerAddresses {
        #[cfg(feature = "native")]
        {
            bootstrap_read_peers(&self.bootstrap, target, self.peer_id())
        }
        #[cfg(not(feature = "native"))]
        {
            bootstrap_read_peers(&self.backend.bootstrap_peers(), target, self.peer_id())
        }
    }

    /// Speculate on already-connected peers on both platforms. Discovery owns
    /// cold dialing; a dead address must not occupy an early GET slot while a
    /// reachable holder is being discovered. Ordinary fallback still sees all
    /// known peers, including those requiring a new connection. Bootstrap
    /// peers are the exception: reads ask them from the start, connected or
    /// not, in a GET slot of their own ([`Network::bootstrap_peers_near`]).
    pub(crate) async fn seed_read_candidates(&self, progress: &ReadProgress) {
        #[cfg(feature = "native")]
        let connected = self.node.connected_peers().await;
        #[cfg(not(feature = "native"))]
        let connected = self.backend.connected_read_peers();
        progress.offer(
            self.known_peers()
                .await
                .into_iter()
                .filter(|node| connected.contains(&node.peer_id))
                .map(|node| {
                    let addrs = node.addresses_by_priority();
                    (node.peer_id, addrs)
                })
                .collect(),
        );
    }

    #[cfg(not(feature = "native"))]
    pub(crate) async fn find_read_peers(
        &self,
        target: &[u8; 32],
        count: usize,
        progress: ReadProgress,
    ) -> Result<PeerAddresses> {
        self.backend.find_read_peers(target, count, progress).await
    }
}

/// Execute a request through the platform adapter and apply the shared response handler.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_and_await_chunk_response<T, E: From<crate::data::error::Error>>(
    network: &Network,
    target_peer: &PeerId,
    message_bytes: Vec<u8>,
    request_id: u64,
    timeout: std::time::Duration,
    peer_addrs: &[MultiAddr],
    response_handler: impl Fn(ant_protocol::ChunkMessageBody) -> Option<std::result::Result<T, E>>,
    send_error: impl FnOnce(String) -> E,
    timeout_error: impl FnOnce() -> E,
) -> std::result::Result<T, E> {
    #[cfg(feature = "native")]
    {
        ant_protocol::send_and_await_chunk_response(
            network.node(),
            target_peer,
            message_bytes,
            request_id,
            timeout,
            peer_addrs,
            response_handler,
            send_error,
            timeout_error,
        )
        .await
    }
    #[cfg(not(feature = "native"))]
    {
        let response = match ant_protocol::ChunkMessage::decode(&message_bytes) {
            Ok(request) => {
                network
                    .backend
                    .request(target_peer, peer_addrs, request, timeout)
                    .await
            }
            Err(error) => Err(crate::data::error::Error::Protocol(error.to_string())),
        };
        let response = match response {
            Ok(response) => response,
            // Preserve browser phase diagnostics and timeout classification. Queue
            // and send expiry must not be reported as a ten-second store wait.
            Err(error @ crate::data::error::Error::Timeout(_)) => return Err(error.into()),
            Err(error) => return Err(send_error(error.to_string())),
        };
        if response.request_id != request_id {
            return Err(timeout_error());
        }
        response_handler(response.body).unwrap_or_else(|| Err(timeout_error()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_ready_false_with_no_peers() {
        let h = NetworkHealth::from_counts(0, 0);
        assert!(!h.write_ready);
        assert_eq!(h.connected_peers, 0);
        assert_eq!(h.routing_table_size, 0);
        assert_eq!(h.rebootstrap_threshold, REBOOTSTRAP_THRESHOLD as u32);
    }

    #[test]
    fn write_ready_false_below_threshold_on_both_signals() {
        // The reporter's incident shape (ant-sdk#232): ~1 reachable peer,
        // empty routing table, stores failing.
        assert!(!NetworkHealth::from_counts(1, 0).write_ready);
        assert!(!NetworkHealth::from_counts(2, 2).write_ready);
    }

    #[test]
    fn write_ready_true_via_connections_despite_low_routing_table() {
        // Client-mode under-reporting observed live on a LAN devnet:
        // rt pinned at 2 with 10 verified connections and stores succeeding.
        // The max() in the formula exists for exactly this state.
        assert!(NetworkHealth::from_counts(10, 2).write_ready);
    }

    #[test]
    fn write_ready_true_via_routing_table_alone() {
        assert!(NetworkHealth::from_counts(0, REBOOTSTRAP_THRESHOLD).write_ready);
    }

    #[test]
    fn write_ready_true_at_exact_threshold_on_connections() {
        assert!(NetworkHealth::from_counts(REBOOTSTRAP_THRESHOLD, 0).write_ready);
    }

    #[test]
    fn counts_saturate_at_u32_max() {
        let h = NetworkHealth::from_counts(usize::MAX, usize::MAX);
        assert_eq!(h.connected_peers, u32::MAX);
        assert_eq!(h.routing_table_size, u32::MAX);
        assert!(h.write_ready);
    }

    fn seed(peer: u8, port: u16) -> MultiAddr {
        format!(
            "/ip4/127.0.0.1/udp/{port}/quic/p2p/{}",
            hex::encode([peer; 32])
        )
        .parse()
        .unwrap()
    }

    #[test]
    fn bootstrap_read_peers_are_nearest_to_the_target_first() {
        let seeds = [seed(0x80, 1), seed(0x11, 2), seed(0x30, 3), seed(0x10, 4)];
        let peers = bootstrap_read_peers(&seeds, &[0x10; 32], &PeerId::from_bytes([0xff; 32]));
        let order: Vec<_> = peers.iter().map(|(peer, _)| peer.as_bytes()[0]).collect();
        // XOR distances from 0x10..: 0x00.., 0x01.., 0x20.., 0x90..
        assert_eq!(order, vec![0x10, 0x11, 0x30, 0x80]);
        assert_eq!(
            bootstrap_read_peers(&seeds, &[0x80; 32], &PeerId::from_bytes([0xff; 32]))[0].0,
            PeerId::from_bytes([0x80; 32])
        );
    }

    #[test]
    fn bootstrap_read_peers_need_a_peer_id_and_leave_out_the_local_peer() {
        let local = PeerId::from_bytes([7; 32]);
        let plain: MultiAddr = "/ip4/127.0.0.1/udp/10000/quic".parse().unwrap();
        // Addresses without a peer ID give reads no bootstrap peers at all.
        assert!(bootstrap_read_peers(std::slice::from_ref(&plain), &[0; 32], &local).is_empty());
        assert!(bootstrap_read_peers(&[], &[0; 32], &local).is_empty());
        // One peer's addresses stay together, once each.
        let peers = bootstrap_read_peers(
            &[
                seed(1, 10000),
                plain,
                seed(1, 10001),
                seed(1, 10000),
                seed(7, 10002),
            ],
            &[0; 32],
            &local,
        );
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, PeerId::from_bytes([1; 32]));
        assert_eq!(peers[0].1, vec![seed(1, 10000), seed(1, 10001)]);
    }

    /// The peer IDs of `seeds`, nearest to `target` first.
    fn nearest_first(seeds: &[MultiAddr], target: &[u8; 32]) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> = seeds.iter().filter_map(|s| s.peer_id()).copied().collect();
        peers.sort_by_key(|peer| ant_protocol::transport::xor_distance(peer.as_bytes(), target));
        peers.dedup();
        peers
    }

    #[test]
    fn a_read_asks_the_nine_bootstrap_peers_nearest_the_target() {
        // The close group and the storage admission margin of two.
        assert_eq!(MAX_BOOTSTRAP_READ_PEERS, 9);
        let local = PeerId::from_bytes([0xff; 32]);
        let ids =
            |peers: PeerAddresses| peers.into_iter().map(|(peer, _)| peer).collect::<Vec<_>>();
        // Thirty seeds, of which the nine nearest differ from target to target.
        let seeds: Vec<_> = (1..=30u8)
            .map(|n| seed(n * 8, 10000 + u16::from(n)))
            .collect();
        for target in [[0x00; 32], [0x42; 32], [0x9c; 32], [0xf0; 32]] {
            let asked = ids(bootstrap_read_peers(&seeds, &target, &local));
            assert_eq!(
                asked,
                nearest_first(&seeds, &target)[..MAX_BOOTSTRAP_READ_PEERS]
            );
            // Fewer than nine: all of them, nearest first.
            let few = &seeds[..MAX_BOOTSTRAP_READ_PEERS - 1];
            let asked = ids(bootstrap_read_peers(few, &target, &local));
            assert_eq!(asked, nearest_first(few, &target));
            assert_eq!(asked.len(), MAX_BOOTSTRAP_READ_PEERS - 1);
        }
        // A peer counts once however many addresses it has, and neither the
        // local peer nor an address without a peer ID takes one of the nine
        // places.
        let plain: MultiAddr = "/ip4/127.0.0.1/udp/10100/quic".parse().unwrap();
        let mut seeds: Vec<_> = (1..=10u8)
            .flat_map(|n| [seed(n, 10000 + u16::from(n)), seed(n, 11000 + u16::from(n))])
            .collect();
        seeds.extend([plain, seed(0, 10200)]);
        let peers = bootstrap_read_peers(&seeds, &[0; 32], &PeerId::from_bytes([0; 32]));
        assert_eq!(
            peers
                .iter()
                .map(|(peer, _)| peer.as_bytes()[0])
                .collect::<Vec<_>>(),
            (1..=9).collect::<Vec<_>>()
        );
        assert!(peers.iter().all(|(_, addrs)| addrs.len() == 2));
    }

    /// A client node built from seeds reads from those of them that carry a
    /// peer ID, and a client given seeds later reads from those instead. The
    /// node is never started, so nothing is dialled.
    #[cfg(feature = "native")]
    #[tokio::test]
    async fn reads_ask_the_seeds_a_network_and_a_client_are_given() {
        let plain: MultiAddr = "/ip4/127.0.0.1/udp/10003/quic".parse().unwrap();
        let seeds = [seed(0x80, 10000), plain, seed(0x10, 10001)];
        let network = Network::unstarted(&seeds, true, false).await.unwrap();
        assert_eq!(network.bootstrap_peers(), &seeds);
        let near = |network: &Network| {
            network
                .bootstrap_peers_near(&[0x11; 32])
                .into_iter()
                .map(|(peer, addrs)| (peer.as_bytes()[0], addrs))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            near(&network),
            vec![
                (0x10, vec![seed(0x10, 10001)]),
                (0x80, vec![seed(0x80, 10000)])
            ]
        );

        let client = crate::data::Client::from_node(Arc::clone(network.node()), Default::default());
        assert!(near(client.network()).is_empty(), "a node alone names none");
        let client = client.with_bootstrap_peers(&[seed(0x42, 10002)]);
        assert_eq!(
            near(client.network()),
            vec![(0x42, vec![seed(0x42, 10002)])]
        );
        // Of twelve, the nine nearest the address read.
        let twelve: Vec<_> = (1..=12u8)
            .map(|n| seed(n * 16, 10010 + u16::from(n)))
            .collect();
        let client = client.with_bootstrap_peers(&twelve);
        let asked: Vec<_> = near(client.network())
            .into_iter()
            .map(|(id, _)| PeerId::from_bytes([id; 32]))
            .collect();
        assert_eq!(asked, nearest_first(&twelve, &[0x11; 32])[..9]);
    }

    #[test]
    fn a_read_asks_nine_of_the_sixteen_bundled_seeds_on_each_transport() {
        let seeds = crate::network_defaults::bundled_bootstrap_seeds().unwrap();
        let webrtc: Vec<MultiAddr> = seeds.webrtc.iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(nearest_first(&seeds.quic, &[0; 32]).len(), 16);
        let local = PeerId::from_bytes([0xff; 32]);
        let ids = |peers: &PeerAddresses| peers.iter().map(|(peer, _)| *peer).collect::<Vec<_>>();
        for target in [[0x42; 32], [0x00; 32], [0xff; 32]] {
            let native = bootstrap_read_peers(&seeds.quic, &target, &local);
            let browser = bootstrap_read_peers(&webrtc, &target, &local);
            assert!(native.iter().all(|(_, addrs)| addrs.len() == 1));
            // The nine of the sixteen nearest the address, in the same order
            // whichever transport reaches them.
            assert_eq!(ids(&native), nearest_first(&seeds.quic, &target)[..9]);
            assert_eq!(ids(&native), ids(&browser));
        }
    }
}
