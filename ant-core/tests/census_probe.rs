//! The node census's probe (`listings_census::probe_peer`) of a node that
//! restarted on the same port while the client still held its connection to
//! it, as a node does when its server restarts it. Nothing closed that
//! connection, so the client still counts the node connected, and a ping
//! over the connection goes unanswered. The probe must not take that for the
//! node being gone: it drops the stale connection and dials the node afresh,
//! and the restarted node answers.
//!
//! Two saorsa-core nodes on loopback, no storage nodes and no chain. The node
//! probed runs on a tokio runtime of its own, so stopping that runtime drops
//! its tasks where they stand: no connection is closed and its peers are told
//! nothing, as when a process is killed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ant_core::data::client::listings_census::{probe_peer, PROBE_TIMEOUT};
use ant_core::data::Network;
use ant_protocol::transport::{
    CoreNodeConfig, IPDiversityConfig, MultiAddr, NodeIdentity, P2PNode, PeerId,
};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn node_config(port: u16, identity: Option<Arc<NodeIdentity>>) -> CoreNodeConfig {
    let mut config = CoreNodeConfig::builder()
        .port(port)
        .ipv6(false)
        .local(true)
        .build()
        .expect("node config");
    config.node_identity = identity;
    config.diversity_config = Some(IPDiversityConfig::permissive());
    config
}

/// A UDP port on loopback that was free a moment ago.
fn free_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|socket| socket.local_addr())
        .expect("a free port")
        .port()
}

/// A node on a tokio runtime of its own, which alone holds it.
struct OwnRuntimeNode {
    runtime: tokio::runtime::Runtime,
    peer_id: PeerId,
}

impl OwnRuntimeNode {
    /// The node with `identity`, listening on `port`; `None` if it can't
    /// start there (the port still held, for one).
    fn start(identity: Arc<NodeIdentity>, port: u16) -> Option<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let node = runtime.block_on(async {
            let node = P2PNode::new(node_config(port, Some(identity))).await.ok()?;
            node.start().await.ok()?;
            Some(Arc::new(node))
        })?;
        let peer_id = *node.peer_id();
        runtime.spawn(async move {
            std::future::pending::<()>().await;
            drop(node);
        });
        Some(Self { runtime, peer_id })
    }

    /// `start`, tried again for a few seconds while the port is still held.
    fn restart(identity: &Arc<NodeIdentity>, port: u16) -> Self {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(node) = Self::start(Arc::clone(identity), port) {
                return node;
            }
            assert!(
                Instant::now() < deadline,
                "the node could not start again on port {port}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stop it as a kill stops a process: its tasks are dropped where they
    /// stand, and no connection is closed.
    fn kill(self) {
        self.runtime.shutdown_background();
    }
}

#[test]
fn a_node_restarted_on_its_port_answers_a_probe_over_a_stale_connection() {
    let port = free_port();
    let identity = Arc::new(NodeIdentity::generate().expect("an identity"));
    let probed = OwnRuntimeNode::start(Arc::clone(&identity), port).expect("start the node");
    let peer = probed.peer_id;
    let address = MultiAddr::quic(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
    let addresses = [address.clone()];

    let client = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let network = client.block_on(async {
        let node = P2PNode::new(node_config(0, None))
            .await
            .expect("the client's node");
        node.start().await.expect("start the client's node");
        let channel = node.connect_peer(&address).await.expect("dial the node");
        let answered = node
            .wait_for_peer_identity(&channel, Duration::from_secs(10))
            .await
            .expect("the node's identity");
        assert_eq!(answered, peer);
        Network::from_node(Arc::new(node))
    });
    client.block_on(async {
        assert!(network.is_peer_connected(&peer).await);
        assert!(
            probe_peer(&network, &peer, &addresses).await,
            "a node up and connected answers a probe"
        );
    });

    // Killed, and back on the same port with the same identity.
    probed.kill();
    let restarted = OwnRuntimeNode::restart(&identity, port);
    assert_eq!(restarted.peer_id, peer);

    client.block_on(async {
        assert!(
            network.is_peer_connected(&peer).await,
            "nothing closed the old connection, so the client must still hold it: \
             otherwise this test checks nothing the probe's dial alone wouldn't"
        );
        let started = Instant::now();
        let answered = probe_peer(&network, &peer, &addresses).await;
        let took = started.elapsed();
        assert!(
            answered,
            "the restarted node must answer the probe, through a fresh dial, within \
             {PROBE_TIMEOUT:?} (took {took:?})"
        );
        // The new connection is the one kept: a probe answers over it.
        assert!(network.is_peer_connected(&peer).await);
        assert!(probe_peer(&network, &peer, &addresses).await);
    });

    restarted.kill();
}
