//! Chunk operations with real EVM payments: the raw chunk path, by the
//! caller's choice, with no envelope.

use crate::support::runner::Case;
use crate::support::{test_client_config, MiniTestnet, CLIENT_NODE};
use ant_core::data::{compute_address, Client};
use ant_protocol::pointer::pointer_address;
use ant_protocol::pqc::api::ml_dsa_65;
use bytes::Bytes;
use futures::future::join_all;
use std::sync::Arc;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network("chunk::round_trip", round_trip),
        Case::on_network(
            "chunk::concurrent_gets_share_one_fetch",
            concurrent_gets_share_one_fetch,
        ),
        Case::on_network(
            "chunk::extended_fallback_reaches_quorum",
            extended_fallback_reaches_quorum,
        ),
        Case::on_network("chunk::duplicate_skips_payment", duplicate_skips_payment),
        Case::on_network("chunk::absent_reads", absent_reads),
        Case::on_network("chunk::no_wallet_fails", no_wallet_fails),
        Case::on_network(
            "chunk::a_kad_read_reads_older_nodes_with_find_node_and_get",
            a_kad_read_reads_older_nodes_with_find_node_and_get,
        ),
        Case::on_network(
            "chunk::a_chunk_the_kad_read_finds_notes_its_holder",
            a_chunk_the_kad_read_finds_notes_its_holder,
        ),
        Case::on_upgrading(
            "chunk::a_kad_read_asks_upgraded_nodes_with_get_or_closer",
            a_kad_read_asks_upgraded_nodes_with_get_or_closer,
        ),
        Case::on_upgrading(
            "chunk::a_recent_holder_is_asked_before_the_kad_lookup",
            a_recent_holder_is_asked_before_the_kad_lookup,
        ),
    ]
}

/// A paid PUT stores the chunk at BLAKE3(content); it reads back, `exists()`
/// sees it, and reading costs nothing, with or without a wallet.
async fn round_trip(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("ant-core chunk e2e test payload");
    let address = client
        .chunk_put(content.clone())
        .await
        .expect("chunk_put should succeed with payment");
    assert_eq!(
        address,
        compute_address(&content),
        "address should be BLAKE3(content)"
    );

    let wallet = client.wallet().expect("wallet should be set");
    let balance_before = wallet.balance_of_tokens().await.expect("balance");
    let chunk = client
        .chunk_get(&address)
        .await
        .expect("chunk_get should succeed")
        .expect("Chunk should be found after storing it");
    assert_eq!(chunk.content.as_ref(), content.as_ref());
    assert_eq!(chunk.address, address);
    assert!(
        client
            .chunk_exists(&address)
            .await
            .expect("exists should succeed"),
        "exists() should return true for stored chunk"
    );
    assert_eq!(
        wallet.balance_of_tokens().await.expect("balance"),
        balance_before,
        "reads are free"
    );

    // A client WITHOUT a wallet on the same node reads it too.
    let node = testnet.node(CLIENT_NODE).expect("client node");
    let no_wallet_client = Client::from_node(node, test_client_config());
    let chunk = no_wallet_client
        .chunk_get(&address)
        .await
        .expect("GET without wallet should succeed (reads are free)")
        .expect("Chunk should be found");
    assert_eq!(chunk.content.as_ref(), content.as_ref());
}

/// Concurrent reads of one chunk share a single fetch: with the cache empty,
/// every concurrent `chunk_get` returns the chunk and no node is asked for it
/// more than once. Without sharing, each reader sends its own GETs and the
/// first holder is asked once per reader.
async fn concurrent_gets_share_one_fetch(testnet: Arc<MiniTestnet>) {
    const READERS: usize = 8;
    let client = testnet.client();

    let content = Bytes::from("ant-core concurrent chunk_get payload");
    let address = client
        .chunk_put(content.clone())
        .await
        .expect("chunk_put should succeed with payment");
    client.chunk_cache().clear();
    let before = testnet.chunk_gets_received(&address);

    let results = join_all((0..READERS).map(|_| client.chunk_get(&address))).await;
    for result in results {
        let chunk = result
            .expect("chunk_get should succeed")
            .expect("Chunk should be found after storing it");
        assert_eq!(chunk.content.as_ref(), content.as_ref());
    }

    testnet.flush_chunk_gets(client.network().node()).await;
    let sent: Vec<usize> = testnet
        .chunk_gets_received(&address)
        .iter()
        .zip(&before)
        .map(|(after, before)| after - before)
        .collect();
    assert!(
        sent.iter().sum::<usize>() >= 1,
        "the chunk should come from the network: {sent:?}"
    );
    assert!(
        sent.iter().all(|&gets| gets <= 1),
        "{READERS} concurrent readers should ask each node at most once: {sent:?}"
    );
}

/// ADR-0002: when initial PUT targets fail, the client falls back to the
/// chunk's genuine next-closest peers — reusing the same `ProofOfPayment`,
/// without re-quoting or re-paying — and still reaches quorum.
///
/// Forces `DEAD_INITIAL_PEERS` (= `CLOSE_GROUP_MAJORITY`) unreachable initial
/// peers, so every initial send fails and a full quorum's worth of stores must
/// come from the *real* next-closest peers in the put-target set. A successful,
/// retrievable store proves the fallback reached those real peers on the single
/// proof produced by one payment.
///
/// Scope: failures here are driven by *unreachable* peers (transport), which
/// exercises the fallback walk + single-proof reuse + quorum end-to-end. The
/// *classification* that routes a full node's `StorageFailed` and a price-floor
/// `PaymentFailed`/`PaymentRequired` into the same fallback is covered by the
/// `classify_put_failure_*` unit test. A live close-group node returning
/// `StorageFailed` (a genuinely full member) needs a node-side capacity hook the
/// in-process MiniTestnet does not expose — tracked as a follow-up.
async fn extended_fallback_reaches_quorum(testnet: Arc<MiniTestnet>) {
    /// Unreachable initial peers to inject; equals `CLOSE_GROUP_MAJORITY` so a
    /// full quorum must be served by the extended fallback.
    const DEAD_INITIAL_PEERS: usize = 4;

    let client = testnet.client();

    let content = Bytes::from("adr-0002 extended fallback payload");
    let address = compute_address(&content);

    let stored = client
        .chunk_put_with_dead_initial_peers(content.clone(), DEAD_INITIAL_PEERS)
        .await
        .expect("extended fallback should reach quorum despite dead initial peers");
    assert_eq!(stored, address, "stored address should be BLAKE3(content)");

    // Retrievable -> quorum was genuinely met via the fallback peers.
    let chunk = client
        .chunk_get(&address)
        .await
        .expect("chunk_get should succeed")
        .expect("chunk should be found after fallback store");
    assert_eq!(chunk.content.as_ref(), content.as_ref());
}

/// A second PUT of stored content finds it stored and pays nothing.
async fn duplicate_skips_payment(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let content = Bytes::from("duplicate payment prevention test");
    let addr1 = client
        .chunk_put(content.clone())
        .await
        .expect("first put should succeed");

    let wallet = client.wallet().expect("wallet should be set");
    let balance_before = wallet.balance_of_tokens().await.expect("balance");
    let addr2 = client
        .chunk_put(content)
        .await
        .expect("duplicate put should succeed");
    assert_eq!(addr1, addr2, "duplicate put should return same address");
    assert_eq!(
        wallet.balance_of_tokens().await.expect("balance"),
        balance_before,
        "duplicate chunk_put should not spend any tokens"
    );
}

/// A chunk nobody stored and a pointer nobody wrote read as absent, not as
/// errors.
async fn absent_reads(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();

    let missing_address = [0xDE; 32];
    assert!(
        client
            .chunk_get(&missing_address)
            .await
            .expect("get for missing address should not error")
            .is_none(),
        "Should return None for non-existent chunk"
    );
    assert!(
        !client
            .chunk_exists(&missing_address)
            .await
            .expect("exists for missing should succeed"),
        "exists() should return false for missing chunk"
    );

    let (pk, _sk) = ml_dsa_65().generate_keypair().expect("keypair");
    assert!(
        client
            .pointer_get(&pointer_address(&pk))
            .await
            .expect("a read of an empty address is not an error")
            .is_none(),
        "nothing was ever written here"
    );
}

/// A client without a wallet can't store: the PUT fails, naming the wallet.
async fn no_wallet_fails(testnet: Arc<MiniTestnet>) {
    let node = testnet.node(CLIENT_NODE).expect("client node");
    let client = Client::from_node(node, test_client_config());

    let result = client
        .chunk_put(Bytes::from("chunk_put without wallet test"))
        .await;
    let err_msg = result
        .expect_err("chunk_put without wallet should fail")
        .to_string();
    assert!(
        err_msg.to_lowercase().contains("wallet"),
        "Error should mention wallet, got: {err_msg}"
    );
}

/// Read requests of either kind, GET or get-or-closer, that the nodes have
/// received for `address`, in total, once every request `client` has sent so
/// far has arrived.
async fn reads_of(testnet: &MiniTestnet, client: &Client, address: &[u8; 32]) -> usize {
    testnet.flush_chunk_gets(client.network().node()).await;
    testnet.chunk_gets_received(address).iter().sum()
}

/// A chunk stored by the funded client for one of these cases, out of every
/// cache: read back only from the nodes.
async fn stored_chunk(testnet: &MiniTestnet, content: &'static str) -> (Bytes, [u8; 32]) {
    let client = testnet.client();
    let content = Bytes::from(content);
    let address = client
        .chunk_put(content.clone())
        .await
        .expect("chunk_put should succeed with payment");
    (content, address)
}

/// ADR-0020 on the network as it is today: no node announces get-or-closer
/// (darwin-node 0.24.0+ds.22 leaves the token out while nodes of earlier
/// releases remain), so the kad read asks every likely holder with FIND_NODE
/// and a GET, and finds the chunk with no get-or-closer request sent. A
/// whole read, as users have it, does the same.
async fn a_kad_read_reads_older_nodes_with_find_node_and_get(testnet: Arc<MiniTestnet>) {
    const {
        assert!(
            !ant_node::node::ANNOUNCES_GET_OR_CLOSER,
            "the pinned darwin-node announces get-or-closer: this case needs a network of nodes \
             that don't, as the network's were before it"
        );
    }
    let (content, address) =
        stored_chunk(&testnet, "ant-core kad read of nodes without get-or-closer").await;
    let reader = testnet.client();
    let get_or_closers = testnet.reads.get_or_closers();
    let before = reads_of(&testnet, &reader, &address).await;

    let chunk = reader
        .chunk_get_kad_only(&address)
        .await
        .expect("the kad read should succeed")
        .expect("the kad read should find a stored chunk");
    assert_eq!(chunk.content.as_ref(), content.as_ref());
    assert!(
        reads_of(&testnet, &reader, &address).await > before,
        "a node that doesn't announce get-or-closer is read with a GET"
    );

    let missing = reader
        .chunk_get_kad_only(&[0xDF; 32])
        .await
        .expect("a kad read of a missing chunk is not an error");
    assert!(missing.is_none(), "a missing chunk is not found");

    let whole = testnet
        .client()
        .chunk_get(&address)
        .await
        .expect("the read should succeed")
        .expect("a stored chunk is found");
    assert_eq!(whole.content.as_ref(), content.as_ref());
    assert_eq!(
        testnet.reads.get_or_closers(),
        get_or_closers,
        "no node announces get-or-closer, so none is sent one"
    );
}

/// The holder cache learns from the kad read: a chunk that read found is
/// read next time from the node that sent it, with one GET and no lookup.
/// Before, the kad read returned a chunk without the peer that sent it, so a
/// re-read paid for the whole lookup again.
async fn a_chunk_the_kad_read_finds_notes_its_holder(testnet: Arc<MiniTestnet>) {
    let (content, address) =
        stored_chunk(&testnet, "ant-core kad read notes the chunk's holder").await;
    // The kad lookup alone finds the chunk on this network, so a fresh
    // client's first read, which asks no holder yet, finds it there.
    let probe = testnet.client();
    assert!(probe
        .chunk_get_kad_only(&address)
        .await
        .expect("the kad read should succeed")
        .is_some());

    let reader = testnet.client();
    let first = reader
        .chunk_get(&address)
        .await
        .expect("the first read should succeed")
        .expect("a stored chunk is found");
    assert_eq!(first.content.as_ref(), content.as_ref());

    reader.chunk_cache().clear();
    let before = reads_of(&testnet, &reader, &address).await;
    let again = reader
        .chunk_get(&address)
        .await
        .expect("the second read should succeed")
        .expect("a stored chunk is found");
    assert_eq!(again.content.as_ref(), content.as_ref());
    assert_eq!(
        reads_of(&testnet, &reader, &address).await - before,
        1,
        "the second read asks only the node that served the first"
    );
}

/// ADR-0020 part way through a rolling upgrade: every other node announces
/// get-or-closer. A client reads chunks from both kinds of node, asking those
/// that announce it with get-or-closer and the rest with FIND_NODE and a GET,
/// and finds every chunk.
async fn a_kad_read_asks_upgraded_nodes_with_get_or_closer(testnet: Arc<MiniTestnet>) {
    const CHUNKS: usize = 16;
    let client = testnet.client();
    let mut stored = Vec::with_capacity(CHUNKS);
    for index in 0..CHUNKS {
        let content = Bytes::from(format!(
            "ant-core read during a rolling upgrade, chunk {index}"
        ));
        let address = client
            .chunk_put(content.clone())
            .await
            .expect("chunk_put should succeed with payment");
        stored.push((content, address));
    }
    let get_or_closers = testnet.reads.get_or_closers();
    testnet.flush_chunk_gets(client.network().node()).await;
    let before: usize = stored
        .iter()
        .map(|(_, address)| testnet.chunk_gets_received(address).iter().sum::<usize>())
        .sum();

    // A fresh client for each chunk: no cache, no holder to ask first.
    let mut readers = Vec::with_capacity(CHUNKS);
    for (content, address) in &stored {
        let reader = testnet.client();
        let chunk = reader
            .chunk_get(address)
            .await
            .expect("the read should succeed")
            .expect("a stored chunk is found");
        assert_eq!(chunk.content.as_ref(), content.as_ref());
        readers.push(reader);
    }
    for reader in &readers {
        testnet.flush_chunk_gets(reader.network().node()).await;
    }
    let reads: usize = stored
        .iter()
        .map(|(_, address)| testnet.chunk_gets_received(address).iter().sum::<usize>())
        .sum::<usize>()
        - before;
    let sent_get_or_closer = testnet.reads.get_or_closers() - get_or_closers;
    assert!(
        sent_get_or_closer > 0,
        "nodes that announce get-or-closer are asked with it"
    );
    assert!(
        reads > sent_get_or_closer,
        "nodes that don't are asked with a GET ({reads} reads, {sent_get_or_closer} get-or-closer)"
    );
}

/// A re-read asks the node that served the chunk last before any lookup:
/// on this network the kad lookup would send get-or-closer requests to the
/// likely holders that announce it, and the re-read sends none, only the
/// holder's GET.
async fn a_recent_holder_is_asked_before_the_kad_lookup(testnet: Arc<MiniTestnet>) {
    let (content, address) =
        stored_chunk(&testnet, "ant-core holder read before the kad lookup").await;
    let reader = testnet.client();
    reader
        .chunk_get(&address)
        .await
        .expect("the first read should succeed")
        .expect("a stored chunk is found");

    reader.chunk_cache().clear();
    let before = reads_of(&testnet, &reader, &address).await;
    let get_or_closers = testnet.reads.get_or_closers();
    let again = reader
        .chunk_get(&address)
        .await
        .expect("the second read should succeed")
        .expect("a stored chunk is found");
    assert_eq!(again.content.as_ref(), content.as_ref());
    assert_eq!(
        reads_of(&testnet, &reader, &address).await - before,
        1,
        "one read request: the holder's GET"
    );
    assert_eq!(
        testnet.reads.get_or_closers(),
        get_or_closers,
        "no lookup step: the holder answered first"
    );
}
