//! Minimal test infrastructure for ant-core E2E tests.
//!
//! Spawns a small local testnet of darwin-node's `AntProtocol` handlers (the
//! revision ant-core/Cargo.toml pins) and an Anvil EVM testnet for real
//! on-chain payment verification. The payment vault on that chain runs the
//! DARWIN vault's code, as the network's does, and beside it the root vault
//! runs DarwinRootVault's frozen code, which every node but
//! [`ROOT_UNAWARE_NODES`] takes root proofs (tag 0x03) in.
//!
//! The `e2e` target starts one such testnet and runs every case on it, with
//! [`runner`]; the targets run by hand start their own.

// This module is compiled into every [[test]] binary that uses it.
// Each binary uses a different subset of methods, so Rust flags
// the unused ones as dead code. All items ARE used by at least
// one test binary.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::used_underscore_binding
)]

use ant_core::data::ClientConfig;
// Node-internal types (test harness needs to *be* a node) — direct
// ant-node import is correct here. ant-node is a dev-dep so this is
// only linked into test binaries.
use ant_node::payment::quote::CommitmentSource;
use ant_node::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig, QuoteGenerator,
    QuotingMetricsTracker,
};
use ant_node::pointer::{service::PointerService, store::PointerStore};
use ant_node::replication::commitment_state::{BuiltCommitment, ResponderCommitmentState};
use ant_node::storage::{AntProtocol, ChunkStore, ChunkStoreConfig};
// Wire / transport / EVM types: route through ant-protocol so the test
// harness exercises the same surface the client does.
use ant_protocol::chunk::{ChunkGetRequest, ChunkMessage, ChunkMessageBody};
use ant_protocol::evm::{testnet::Testnet, Network as EvmNetwork, RewardsAddress, Wallet};
use ant_protocol::pqc::ops::{MlDsaOperations, MlDsaSecretKey};
use ant_protocol::transport::{
    CoreNodeConfig, IPDiversityConfig, MlDsa65, MultiAddr, NodeIdentity, P2PEvent, P2PNode,
};
use ant_protocol::{CLOSE_GROUP_SIZE, MAX_WIRE_MESSAGE_SIZE};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;

pub mod runner;

const BOOTSTRAP_COUNT: usize = 2;
/// The pause between two nodes joining. Started all at once, nodes met only
/// the peers that had joined before their own lookup, and in a 20-node
/// testnet a pair of them never met in 180 s; 50 ms apart, every node knows
/// every other within about 15 s (it was 200 ms, from the days of
/// unoptimised signature checks).
const SPAWN_DELAY: Duration = Duration::from_millis(50);
const STABILIZATION_TIMEOUT_SECS: u64 = 180;

/// The DHT request timeout (saorsa-core's `connection_timeout`) of every
/// testnet node, as this harness has always set it for its testnets.
const DHT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// darwin-node's answer to a merkle (batch) payment. Its nodes give it at
/// quote time to every merkle candidate request, before anything is signed,
/// and to every merkle-tagged proof on a PUT: a batch is paid on-chain before
/// any storer sees it, so a refusal after payment would lose the money.
pub use ant_node::payment::BATCH_PAYMENTS_REFUSED;

/// What `wallet` has spent, as its chain shows it: the transactions it has
/// sent (its nonce) and the tokens it holds. Unchanged across a call, nothing
/// was paid in it.
pub async fn wallet_spend(wallet: &Wallet) -> (u64, ant_protocol::evm::U256) {
    use alloy::providers::Provider;
    let sent = wallet
        .to_provider()
        .get_transaction_count(wallet.address())
        .await
        .expect("read the wallet's nonce");
    let tokens = wallet
        .balance_of_tokens()
        .await
        .expect("read the wallet's tokens");
    (sent, tokens)
}

/// Check that `error` is darwin-node's refusal of a batch payment, typed as
/// such ([`ant_core::data::Error::BatchPaymentsRefused`]) and carrying the
/// nodes' sentence: the nodes refused the merkle candidate requests, so no
/// batch was quoted, let alone paid. It is not a refusal of this client's
/// settlement version (`ClientUpdateRequired`), which would stop the client
/// paying per chunk too.
pub fn assert_batch_refused(error: &ant_core::data::Error) {
    let text = error.to_string();
    assert!(
        matches!(error, ant_core::data::Error::BatchPaymentsRefused(_)),
        "expected darwin-node's refusal of batch payments (BatchPaymentsRefused), got: {error:?}"
    );
    assert!(
        text.contains(BATCH_PAYMENTS_REFUSED),
        "the refusal must carry the nodes' sentence, got: {text}"
    );
}

/// Nodes in a testnet.
///
/// A client asks 16 peers for a merkle candidate pool, and on a network where
/// it knows fewer it gives up before asking any node, so the nodes' refusal
/// of the batch would never be seen. The client's own node is not one of the
/// peers it asks, so 17 nodes is the floor for the refusal pins; 20 leaves a
/// margin and gives every close group of `CLOSE_GROUP_SIZE` (7) room around
/// it.
pub const DEFAULT_NODE_COUNT: usize = 20;

/// The node the e2e cases build their clients on. Its own lookups leave it
/// out, so it is never one of the close group a case addresses.
pub const CLIENT_NODE: usize = 3;

/// The nodes that know no root vault, as a node on a build before root
/// payments: each answers a quote request at the root vault's settlement
/// version `StorerUpdateRequired`, and refuses every root proof. A record
/// whose close group holds one is paid through the per-quote vault.
pub const ROOT_UNAWARE_NODES: [usize; 2] = [17, 19];

/// Test rewards address (20 bytes, all 0x01).
const TEST_REWARDS_ADDRESS: [u8; 20] = [0x01; 20];
/// Max records for quoting metrics.
const TEST_MAX_RECORDS: usize = 1280;

/// `ClientConfig` tuned for the in-process `MiniTestnet`.
///
/// Production defaults (`quote_timeout_secs = 10`, `store_timeout_secs = 10`)
/// assume dedicated CPU and residential-grade network timing. E2E tests
/// spawn a full P2P network inside a single CI VM, so all QUIC handshakes,
/// DHT lookups, and payment round-trips compete for the same cores. On
/// heavily-virtualised runners (macOS GitHub Actions in particular), the
/// 10 s per-peer timeout fires before the slowest peer can finish its
/// handshake, which can surface as `InsufficientPeers`.
///
/// 60 s is deliberately conservative: in the happy path everything completes
/// in well under a second, so the larger budget only shows up on flakes.
#[must_use]
pub fn test_client_config() -> ClientConfig {
    ClientConfig {
        quote_timeout_secs: 60,
        store_timeout_secs: 60,
        ..Default::default()
    }
}

pub struct TestNode {
    pub p2p_node: Arc<P2PNode>,
    pub protocol: Arc<AntProtocol>,
    /// Which pointer requests the node takes off the wire and ignores.
    pub pointer_silence: Arc<PointerSilence>,
    /// Chunk GET requests the node has received.
    pub chunk_gets: Arc<ChunkGetCounts>,
    /// Cleared once the node is shut down.
    up: AtomicBool,
    handler: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TestNode {
    /// Whether the node is still running.
    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }
}

/// Switches that make a node ignore pointer requests while staying in the
/// network, as a peer that is up but unreachable for them would.
///
/// A silenced request is read off the wire and dropped: nothing is stored and
/// nothing is answered, so the sender waits out its own timeout. Everything
/// else the node handles as usual. Lets a test choose how many of a close group
/// a read or a write actually reaches, over the real transport.
///
/// The decision is taken as each message arrives, before any work is spawned
/// for it, so a request that arrived while its kind was silenced is dropped
/// even if the switch is lifted a moment later.
#[derive(Default)]
pub struct PointerSilence {
    /// Ignore pointer GETs.
    pub gets: AtomicBool,
    /// Ignore pointer PUTs.
    pub puts: AtomicBool,
}

impl PointerSilence {
    /// Whether `data` is a pointer request this node is ignoring.
    fn drops(&self, data: &[u8]) -> bool {
        let gets = self.gets.load(Ordering::Relaxed);
        let puts = self.puts.load(Ordering::Relaxed);
        if !gets && !puts {
            return false;
        }
        match ChunkMessage::decode(data) {
            Ok(ChunkMessage {
                body: ChunkMessageBody::PointerGetRequest(_),
                ..
            }) => gets,
            Ok(ChunkMessage {
                body: ChunkMessageBody::PointerPutRequest(_),
                ..
            }) => puts,
            _ => false,
        }
    }
}

/// Chunk GET requests a node has received, by chunk address, counted as each
/// message arrives and before the node handles it.
#[derive(Default)]
pub struct ChunkGetCounts(Mutex<HashMap<[u8; 32], usize>>);

impl ChunkGetCounts {
    /// A GET request is a few dozen bytes, so anything larger, such as a PUT
    /// carrying a chunk, is not decoded.
    const MAX_GET_REQUEST_BYTES: usize = 1024;

    fn note(&self, data: &[u8]) {
        if data.len() > Self::MAX_GET_REQUEST_BYTES {
            return;
        }
        if let Ok(ChunkMessage {
            body: ChunkMessageBody::GetRequest(request),
            ..
        }) = ChunkMessage::decode(data)
        {
            *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(request.address)
                .or_default() += 1;
        }
    }

    /// GET requests received for `address`.
    pub fn get(&self, address: &[u8; 32]) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(address)
            .copied()
            .unwrap_or(0)
    }
}

pub struct MiniTestnet {
    pub nodes: Vec<TestNode>,
    _temp_dirs: Vec<tempfile::TempDir>,
    /// Keeps the Anvil process alive for the lifetime of the testnet.
    _testnet: Testnet,
    wallet: Wallet,
    evm_network: EvmNetwork,
    /// The root vault on the chain, running DarwinRootVault's frozen code.
    root_vault: ant_protocol::evm::Address,
    /// The funded wallet's key, which the root vault's wallet signs with.
    private_key: String,
}

/// What [`MiniTestnet::spawn_node`] starts.
struct Spawned {
    node: Arc<P2PNode>,
    protocol: Arc<AntProtocol>,
    pointer_silence: Arc<PointerSilence>,
    chunk_gets: Arc<ChunkGetCounts>,
    handler: tokio::task::JoinHandle<()>,
}

impl MiniTestnet {
    /// Start a testnet with the given number of nodes. Nodes emit baseline
    /// `(0, None)` quotes (no commitment source wired).
    pub async fn start(node_count: usize) -> Self {
        Self::start_inner(node_count, None).await
    }

    /// ADR-0004: start a testnet where every node carries a live storage
    /// commitment over `key_count` synthetic keys, so they emit COMMITMENT-BOUND
    /// quotes (price = `calculate_price(key_count)`, pinned, commitment shipped
    /// in the quote response). Exercises the full node→client→storer binding
    /// handshake against real QUIC + Anvil.
    pub async fn start_with_commitments(node_count: usize, key_count: u32) -> Self {
        Self::start_inner(node_count, Some(key_count)).await
    }

    /// Anvil, with the DARWIN vault's code as the payment vault, so payment
    /// records are write-once: a quote hash's first non-zero payment is kept
    /// and later ones are skipped (evmlib's test vault lets a later payment
    /// overwrite the record instead). Then `node_count` nodes, each on a port
    /// the system picks, so no two testnets on one machine collide.
    async fn start_inner(node_count: usize, commitment_key_count: Option<u32>) -> Self {
        // Start Anvil EVM testnet FIRST
        let testnet = Testnet::new().await.expect("start Anvil testnet");

        // Create funded wallet from the same Anvil instance
        let private_key = testnet
            .default_wallet_private_key()
            .expect("get wallet key");
        let evm_network = deploy_darwin_vault(&testnet.to_network(), &private_key).await;
        let wallet = Wallet::new_from_private_key(evm_network.clone(), &private_key)
            .expect("create funded wallet");
        let root_vault = deploy_root_vault(&evm_network, &private_key).await;
        // The root vault as the nodes take it: given in their network's
        // config, as `--evm-root-vault` gives it.
        let root_setting = ant_node::config::EvmNetworkConfig::Custom {
            rpc_url: evm_network.rpc_url().to_string(),
            payment_token_address: format!("{:#x}", evm_network.payment_token_address()),
            payment_vault_address: format!("{:#x}", evm_network.payment_vault_address()),
            payment_vault_deployment_block: None,
            root_vault_address: Some(format!("{root_vault:#x}")),
        }
        .root_vault()
        .expect("the root vault setting");
        assert!(
            root_setting.vault().is_some(),
            "the nodes know the root vault"
        );
        let root_of = |index: usize| {
            if ROOT_UNAWARE_NODES.contains(&index) {
                ant_node::config::RootVaultSetting::None
            } else {
                root_setting
            }
        };

        let bootstrap_count = BOOTSTRAP_COUNT.min(node_count);
        let temp_dirs: Vec<tempfile::TempDir> = (0..node_count)
            .map(|_| tempfile::TempDir::new().expect("create temp dir"))
            .collect();
        let mut spawned = Vec::with_capacity(node_count);

        // Phase 1: the bootstrap nodes, one after another, each joining the
        // ones before it.
        let mut bootstrap_addrs: Vec<MultiAddr> = Vec::new();
        for (i, temp_dir) in temp_dirs.iter().enumerate().take(bootstrap_count) {
            let node = Self::spawn_node(
                &bootstrap_addrs,
                temp_dir.path(),
                &evm_network,
                root_of(i),
                i,
                commitment_key_count,
            )
            .await;
            bootstrap_addrs.extend(node.node.listen_addrs().await);
            spawned.push(node);
        }

        // Phase 2: every other node, one after another, through the
        // bootstrap nodes.
        for (i, temp_dir) in temp_dirs.iter().enumerate().skip(bootstrap_count) {
            let node = Self::spawn_node(
                &bootstrap_addrs,
                temp_dir.path(),
                &evm_network,
                root_of(i),
                i,
                commitment_key_count,
            )
            .await;
            spawned.push(node);
            sleep(SPAWN_DELAY).await;
        }

        let nodes: Vec<TestNode> = spawned
            .into_iter()
            .map(|node| TestNode {
                p2p_node: node.node,
                protocol: node.protocol,
                pointer_silence: node.pointer_silence,
                chunk_gets: node.chunk_gets,
                up: AtomicBool::new(true),
                handler: Mutex::new(Some(node.handler)),
            })
            .collect();

        // Phase 3: Wait for DHT convergence.
        // Every node's routing table must know about all other nodes
        // so that `find_closest_nodes` returns the full close group.
        // A merkle candidate pool asks at least 16 peers, which darwin-node
        // then refuses. For small networks, require all peers. For large
        // ones, require at least 20.
        let min_routing_table_size = if node_count > 20 { 20 } else { node_count - 1 };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(STABILIZATION_TIMEOUT_SECS);

        loop {
            let mut short = 0;
            for n in &nodes {
                if n.p2p_node.dht().get_routing_table_size().await < min_routing_table_size {
                    short += 1;
                }
            }

            if short == 0 {
                break;
            }

            if tokio::time::Instant::now() > deadline {
                eprintln!(
                    "WARNING: {short} of {node_count} nodes still know fewer than \
                     {min_routing_table_size} peers after {STABILIZATION_TIMEOUT_SECS} s"
                );
                break;
            }

            sleep(Duration::from_millis(500)).await;
        }

        // The in-process E2E harness builds clients from one of the storage
        // nodes. Saorsa's witnessed client lookup filters that local peer out,
        // while node-side payment verification uses a self-inclusive local
        // close-group view. In tiny random testnets that can make an otherwise
        // valid paid median issuer fall just outside a storer's local top-7.
        // Keep the production live-DHT check in normal builds, but use
        // ant-node's test-only override here so these client E2Es exercise
        // payment/proof/storage behaviour without depending on that topology
        // artifact.
        let paid_quote_close_group_override: Vec<[u8; 32]> = nodes
            .iter()
            .map(|test_node| *test_node.p2p_node.peer_id().as_bytes())
            .collect();
        for test_node in &nodes {
            test_node
                .protocol
                .payment_verifier_arc()
                .set_paid_quote_close_group_for_tests(paid_quote_close_group_override.clone());
        }

        // Approve token spend for the unified payment vault contract
        let vault_address = evm_network.payment_vault_address();
        wallet
            .approve_to_spend_tokens(*vault_address, ant_protocol::evm::U256::MAX)
            .await
            .expect("approve payment vault token spend");

        Self {
            nodes,
            _temp_dirs: temp_dirs,
            _testnet: testnet,
            wallet,
            evm_network,
            root_vault,
            private_key,
        }
    }

    /// The node at `index`, while it runs.
    pub fn node(&self, index: usize) -> Option<Arc<P2PNode>> {
        self.nodes
            .get(index)
            .filter(|node| node.is_up())
            .map(|node| Arc::clone(&node.p2p_node))
    }

    /// The nodes still running.
    pub fn running(&self) -> impl Iterator<Item = &TestNode> {
        self.nodes.iter().filter(|node| node.is_up())
    }

    /// A client on [`CLIENT_NODE`] with [`test_client_config`], paying from
    /// the funded wallet.
    pub fn client(&self) -> ant_core::data::Client {
        self.client_with(test_client_config())
    }

    /// A client on [`CLIENT_NODE`] with `config`, paying from the funded
    /// wallet.
    pub fn client_with(&self, config: ClientConfig) -> ant_core::data::Client {
        let node = self.node(CLIENT_NODE).expect("the client node runs");
        ant_core::data::Client::from_node(node, config).with_wallet(self.wallet.clone())
    }

    /// A client on [`CLIENT_NODE`] with [`test_client_config`], paying
    /// through the root vault ([`ant_core::data::Client::with_root_payments`])
    /// from the funded wallet.
    pub fn root_client(&self) -> ant_core::data::Client {
        self.client()
            .with_root_payments(self.root_wallet())
            .expect("a root client")
    }

    /// The funded wallet's key, paying the root vault.
    pub fn root_wallet(&self) -> Wallet {
        ant_core::config::root_wallet(&self.evm_network, self.root_vault, &self.private_key, None)
            .expect("the root vault's wallet")
    }

    /// The root vault's address.
    pub fn root_vault(&self) -> ant_protocol::evm::Address {
        self.root_vault
    }

    /// The peer ids of the nodes that know no root vault
    /// ([`ROOT_UNAWARE_NODES`]).
    pub fn root_unaware_peers(&self) -> Vec<[u8; 32]> {
        ROOT_UNAWARE_NODES
            .iter()
            .map(|&index| *self.nodes[index].p2p_node.peer_id().as_bytes())
            .collect()
    }

    /// Let every node handle every pointer request again.
    pub fn reset_switches(&self) {
        for node in &self.nodes {
            node.pointer_silence.gets.store(false, Ordering::Relaxed);
            node.pointer_silence.puts.store(false, Ordering::Relaxed);
        }
    }

    /// Get a reference to the funded wallet for payment operations.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Get the EVM network configuration (Anvil testnet).
    pub fn evm_network(&self) -> &EvmNetwork {
        &self.evm_network
    }

    #[allow(clippy::too_many_lines)]
    async fn spawn_node(
        bootstrap_peers: &[MultiAddr],
        data_dir: &std::path::Path,
        evm_network: &EvmNetwork,
        root_vault: ant_node::config::RootVaultSetting,
        node_index: usize,
        commitment_key_count: Option<u32>,
    ) -> Spawned {
        // Generate ML-DSA-65 identity for this node
        let identity = Arc::new(NodeIdentity::generate().expect("generate node identity"));

        // IPv4-only is intentional for these loopback-only tests: everything
        // binds to 127.0.0.1 on the local host, so dual-stack would add no
        // value and pulls in v6 loopback quirks on some CI runners. Port 0:
        // the system picks a free port, which the node then lists among its
        // listen addresses.
        let mut core_config = CoreNodeConfig::builder()
            .port(0)
            .ipv6(false)
            .local(true)
            .max_message_size(MAX_WIRE_MESSAGE_SIZE)
            .build()
            .expect("create core config");

        core_config.bootstrap_peers = bootstrap_peers.to_vec();
        core_config.connection_timeout = DHT_REQUEST_TIMEOUT;
        core_config.node_identity = Some(Arc::clone(&identity));
        core_config.diversity_config = Some(IPDiversityConfig::permissive());

        let node = Arc::new(P2PNode::new(core_config).await.expect("create P2P node"));
        node.start().await.expect("start P2P node");

        // Create the chunk store. ant-node #216 replaced the LMDB chunk store
        // with one file per chunk; `AntProtocol::new` now takes an
        // `Arc<ChunkStore>`. ant-node 0.22.0 dropped the LMDB map size and the
        // migration config along with the old backend, so the store comes up
        // on the file backend with nothing to migrate.
        let storage_config = ChunkStoreConfig {
            root_dir: data_dir.to_path_buf(),
            verify_on_read: true,
            disk_reserve: 0,
        };
        let storage = Arc::new(
            ChunkStore::new(storage_config)
                .await
                .expect("create storage"),
        );

        // Each node gets a unique rewards address so tests exercise
        // recipient-binding verification (the verifier checks that its own
        // address appears in the proof).
        let mut addr_bytes = TEST_REWARDS_ADDRESS;
        addr_bytes[19] = u8::try_from(node_index % 256).unwrap_or(0);
        let rewards_address = RewardsAddress::new(addr_bytes);

        // Create payment verifier with the Anvil EVM network
        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                network: evm_network.clone(),
                root_vault: root_vault.vault(),
            },
            cache_capacity: 1000,
            close_group_size: CLOSE_GROUP_SIZE,
            local_rewards_address: rewards_address,
            // Shadow mode (enforce: false) — the harness keeps the node's
            // default price-floor policy so admissions behave as they did
            // before ant-node #176 added the floor.
            price_floor: PriceFloorConfig::default(),
        };
        let payment_verifier = Arc::new(PaymentVerifier::new(payment_config));
        let metrics_tracker = QuotingMetricsTracker::new(TEST_MAX_RECORDS);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing so quotes are properly signed and verifiable
        let pub_key_bytes = identity.public_key().as_bytes().to_vec();
        let sk_bytes = identity.secret_key_bytes().to_vec();
        let sk =
            { MlDsaSecretKey::from_bytes(&sk_bytes).expect("deserialize ML-DSA-65 secret key") };
        quote_generator.set_signer(pub_key_bytes, move |msg| {
            let ml_dsa = MlDsa65::new();
            ml_dsa
                .sign(&sk, msg)
                .map_or_else(|_| vec![], |sig| sig.as_bytes().to_vec())
        });

        // Pointers live beside the chunks under the same root, exactly as a
        // real node wires them: without a pointer service the node refuses
        // every pointer message, which would make a pointer E2E test prove
        // nothing about the code a node actually runs.
        let pointer_store = PointerStore::new(data_dir)
            .await
            .expect("create pointer store");
        let pointers = PointerService::new(pointer_store)
            .with_chunk_store(Arc::clone(&storage))
            .with_payments(Arc::clone(&payment_verifier));

        // Create protocol handler
        let protocol = Arc::new(
            AntProtocol::new(storage, payment_verifier, Arc::new(quote_generator))
                .with_pointer_service(pointers),
        );
        // Wire the P2P node into the protocol so direct PUT storage-admission
        // and payment closeness checks use the node's live DHT view.
        protocol.attach_p2p_node(Arc::clone(&node));

        // ADR-0004: optionally give this node a live storage commitment so it
        // emits COMMITMENT-BOUND quotes (price = calculate_price(key_count),
        // pinned, with the signed commitment shipped in the quote response).
        // Without this the node has no commitment source and emits baseline
        // `(0, None)` quotes — the path the rest of the suite exercises.
        if let Some(key_count) = commitment_key_count {
            let source = build_commitment_source(key_count, &identity);
            protocol.attach_commitment_source(source);
        }

        // Start message handler loop
        let pointer_silence = Arc::new(PointerSilence::default());
        let handler_silence = Arc::clone(&pointer_silence);
        let chunk_gets = Arc::new(ChunkGetCounts::default());
        let handler_gets = Arc::clone(&chunk_gets);
        let handler_node = Arc::clone(&node);
        let handler_protocol = Arc::clone(&protocol);
        let handler = tokio::spawn(async move {
            let mut events = handler_node.subscribe_events();
            loop {
                match events.recv().await {
                    Ok(P2PEvent::Message {
                        topic,
                        source: Some(source_peer),
                        data,
                        ..
                    }) => {
                        if topic == ant_protocol::CHUNK_PROTOCOL_ID {
                            handler_gets.note(&data);
                            if handler_silence.drops(&data) {
                                continue;
                            }
                        }
                        let protocol = Arc::clone(&handler_protocol);
                        let node = Arc::clone(&handler_node);
                        let topic_clone = topic.clone();
                        tokio::spawn(async move {
                            if topic_clone != ant_protocol::CHUNK_PROTOCOL_ID {
                                return;
                            }
                            match protocol.try_handle_request(&data).await {
                                Ok(Some(response_bytes)) => {
                                    if let Err(e) = node
                                        .send_message(
                                            &source_peer,
                                            &topic_clone,
                                            response_bytes.to_vec(),
                                            &[],
                                        )
                                        .await
                                    {
                                        eprintln!("ERROR: node {node_index} failed to send response to {source_peer}: {e}");
                                    }
                                }
                                Ok(None) => {
                                    // Non-request message (e.g. response) — nothing to reply
                                }
                                Err(e) => {
                                    eprintln!(
                                        "ERROR: node {node_index} try_handle_request failed: {e}"
                                    );
                                }
                            }
                        });
                    }
                    Ok(P2PEvent::Message { source: None, .. }) => {
                        eprintln!("WARNING: node {node_index} received message with no source");
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("WARNING: node {node_index} handler lagged, dropped {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Spawned {
            node,
            protocol,
            pointer_silence,
            chunk_gets,
            handler,
        }
    }

    /// Shut down a node by index, simulating a failure: its handler stops
    /// and its transport closes. The slot stays in `nodes`, no longer up.
    pub async fn shutdown_node(&self, index: usize) {
        if let Some(node) = self.nodes.get(index) {
            node.up.store(false, Ordering::SeqCst);
            if let Some(task) = lock(&node.handler).take() {
                task.abort();
            }
            let _ = node.p2p_node.shutdown().await;
        }
    }

    /// Chunk GET requests each node has received for `address`, in node order.
    pub fn chunk_gets_received(&self, address: &[u8; 32]) -> Vec<usize> {
        self.nodes
            .iter()
            .map(|node| node.chunk_gets.get(address))
            .collect()
    }

    /// Waits until every other running node has counted a sentinel GET sent
    /// from `sender` after the caller's GETs. Call it before
    /// [`Self::chunk_gets_received`] so a GET still in transit, such as an
    /// unanswered hedge, is counted too.
    ///
    /// A GET's send returns once the node's QUIC stack has acknowledged the
    /// stream, so every GET `sender` sent before this call has reached the
    /// node before its sentinel is sent, and a node accepts one peer's
    /// streams in the order they were opened.
    pub async fn flush_chunk_gets(&self, sender: &P2PNode) {
        const SENTINEL: [u8; 32] = [0xA5; 32];
        let message = ChunkMessage {
            request_id: u64::MAX,
            body: ChunkMessageBody::GetRequest(ChunkGetRequest::new(SENTINEL)),
        }
        .encode()
        .expect("encode sentinel GET");

        let mut pending = Vec::new();
        for node in self.running() {
            let p2p_node = &node.p2p_node;
            if p2p_node.peer_id() == sender.peer_id() {
                continue;
            }
            let expected = node.chunk_gets.get(&SENTINEL) + 1;
            sender
                .send_message(
                    p2p_node.peer_id(),
                    ant_protocol::CHUNK_PROTOCOL_ID,
                    message.clone(),
                    &p2p_node.listen_addrs().await,
                )
                .await
                .expect("send sentinel GET");
            pending.push((node, expected));
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while pending
            .iter()
            .any(|(node, expected)| node.chunk_gets.get(&SENTINEL) < *expected)
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "nodes did not count the sentinel GET within 10s"
            );
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Count how many nodes are still running.
    pub fn running_node_count(&self) -> usize {
        self.running().count()
    }

    pub async fn teardown(&self) {
        // 1. Abort handler tasks first so they stop processing messages
        for node in &self.nodes {
            if let Some(task) = lock(&node.handler).take() {
                task.abort();
            }
        }

        // 2. Gracefully shut down each P2P node — this sends DHT leave
        //    messages, closes QUIC endpoints, and releases ports so the
        //    OS can reclaim them before the next testnet starts.
        for node in self.running() {
            let _ = node.p2p_node.shutdown().await;
        }
    }
}

/// `mutex`'s value, whether or not a panicking case poisoned it.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// ADR-0004: build a live `ResponderCommitmentState` holding one current
/// commitment over `key_count` synthetic keys, signed by `identity`'s ML-DSA-65
/// key and bound to its peer id (`BLAKE3(pub_key)`). Returned as the
/// `CommitmentSource` the quote generator prices against — so the node emits a
/// commitment-bound quote (`calculate_price(key_count)`, pinned) and ships the
/// signed commitment in the quote response. The commitment is real: it passes
/// the storer's signature, peer-binding, and hash==pin checks.
fn build_commitment_source(key_count: u32, identity: &NodeIdentity) -> Arc<dyn CommitmentSource> {
    // Use the SAME identity→commitment-key conversion the replication engine
    // uses in production (`MlDsaSecretKey::from_bytes(MlDsa65, identity bytes)`),
    // so the commitment is signed by the node's real key and binds to its real
    // peer id — exactly what the storer's cross-check verifies.
    use ant_protocol::pqc::api::{MlDsaSecretKey, MlDsaVariant};

    let pub_key = identity.public_key().as_bytes().to_vec();
    let peer_id = *blake3::hash(&pub_key).as_bytes();
    let sk_bytes = identity.secret_key_bytes().to_vec();
    let sk = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
        .expect("deserialize ML-DSA-65 secret key");

    // `key_count` distinct (key, bytes_hash) leaves — the commitment attests
    // exactly this many keys, which becomes the quote's committed_key_count.
    let entries: Vec<([u8; 32], [u8; 32])> = (0..key_count)
        .map(|i| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            let mut b = [1u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            (k, b)
        })
        .collect();

    let built =
        BuiltCommitment::build(entries, &peer_id, &sk, &pub_key).expect("build storage commitment");
    let state = ResponderCommitmentState::new();
    state.rotate(built);
    Arc::new(state)
}

/// The DARWIN vault's creation code, without its constructor arguments: the
/// creation code of payment-vault's `deployments/darwin-vault-2026-10-06/initcode.hex`.
pub const DARWIN_VAULT_CREATION_CODE: &str =
    include_str!("../fixtures/darwin-vault-creation-code.hex");

/// Deploy the DARWIN vault's code on `network`'s chain, paid in its token,
/// with the DARWIN vault's batch limit (512), and return the network with it
/// as the payment vault.
pub async fn deploy_darwin_vault(network: &EvmNetwork, private_key: &str) -> EvmNetwork {
    use alloy::network::{EthereumWallet, TransactionBuilder};
    use alloy::primitives::U256;
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::rpc::types::TransactionRequest;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol_types::SolValue;

    let mut code = hex::decode(DARWIN_VAULT_CREATION_CODE.trim()).expect("vault creation code");
    code.extend((*network.payment_token_address(), U256::from(512u64)).abi_encode_params());
    let signer: PrivateKeySigner = private_key.parse().expect("wallet key");
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(network.rpc_url().clone());
    let receipt = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(code))
        .await
        .expect("send vault deployment")
        .get_receipt()
        .await
        .expect("vault deployment receipt");
    assert!(receipt.status(), "vault deployment reverted");
    let vault = receipt.contract_address.expect("vault address");
    EvmNetwork::Custom(ant_protocol::evm::CustomNetwork {
        rpc_url_http: network.rpc_url().clone(),
        payment_token_address: *network.payment_token_address(),
        payment_vault_address: vault,
    })
}

/// DarwinRootVault's frozen creation code, without its constructor
/// arguments: the code deployed on Robinhood Chain at
/// `0xf6675722f443132b045857546E57e35360Bb03b9`, whose keccak256 is
/// [`DARWIN_ROOT_VAULT_CREATION_CODE_HASH`].
pub const DARWIN_ROOT_VAULT_CREATION_CODE: &str =
    include_str!("../fixtures/darwin-root-vault-creation-code.hex");

/// The keccak256 of [`DARWIN_ROOT_VAULT_CREATION_CODE`]'s bytes.
pub const DARWIN_ROOT_VAULT_CREATION_CODE_HASH: &str =
    "0df241a9d350881389969481be85af33dcb4eebde6e577d924675588aa1857c3";

/// Deploy DarwinRootVault's frozen code on `network`'s chain, paid in its
/// token, with the production leaf limit (512), and return its address.
pub async fn deploy_root_vault(
    network: &EvmNetwork,
    private_key: &str,
) -> ant_protocol::evm::Address {
    use alloy::network::{EthereumWallet, TransactionBuilder};
    use alloy::primitives::U256;
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::rpc::types::TransactionRequest;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol_types::SolValue;

    let mut code =
        hex::decode(DARWIN_ROOT_VAULT_CREATION_CODE.trim()).expect("root vault creation code");
    assert_eq!(
        hex::encode(alloy::primitives::keccak256(&code)),
        DARWIN_ROOT_VAULT_CREATION_CODE_HASH,
        "the frozen creation code"
    );
    code.extend((*network.payment_token_address(), U256::from(512u64)).abi_encode_params());
    let signer: PrivateKeySigner = private_key.parse().expect("wallet key");
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(network.rpc_url().clone());
    let receipt = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(code))
        .await
        .expect("send root vault deployment")
        .get_receipt()
        .await
        .expect("root vault deployment receipt");
    assert!(receipt.status(), "root vault deployment reverted");
    receipt.contract_address.expect("root vault address")
}
