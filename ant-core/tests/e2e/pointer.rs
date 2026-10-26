//! End-to-end tests for pointers against a local testnet with real EVM payments.
//!
//! Real nodes, real QUIC between them, real Anvil settlement, and the client's
//! own create / update / put / get / resolve path over the top.
//!
//! Most tests go through the public client API only. Some also need what no
//! client call produces on purpose: a state that reached only part of the close
//! group, or a request no honest client would send. Those pay for a state the
//! way the client does and then either
//!
//! - send it to one close-group node **over QUIC**, from the client's own node,
//!   so transport, dispatch, payment verification and the store all run as
//!   they do for any peer's PUT (`put_over_quic`); or
//! - hand it to chosen nodes through each node's request handler directly, to
//!   place a fork or a lagging replica (`store_on`). That exercises the same
//!   dispatch, payment verification, closeness gate and merge, but not the
//!   transport, and it is not evidence about the client's write path.
//!
//! To make a read or a write reach only part of the group through the client's
//! own path, a test tells every node except the ones meant to answer to ignore
//! pointer GETs or PUTs while staying in the network (`support::PointerSilence`).
//! The client then waits out its timeout on them, exactly as it would on
//! unreachable peers. Silencing the whole network rather than chosen group
//! members keeps these tests independent of which seven peers the client's own
//! lookup settles on: that lookup keeps only peers that answer it in time, so
//! under load it can swap the peer at the edge of the group for the next one
//! out — which is then silent too.
//!
//! Tests that rely on which peers form the close group check that the group
//! has not changed before they read, so a moved group fails loudly rather than
//! as a puzzling assertion.
//!
//! The read and merge rules themselves (four answers, two that agree, the
//! merge winner in any order, a stored state resubmitted, raced final
//! states) are pinned without nodes by `src/data/client/pointer.rs`'s unit
//! tests and darwin-node's `tests/pointer_convergence.rs`; a resolve's
//! cycles, broken chains and depth limit by the unit tests of
//! `resolve_chain`.

use crate::support::runner::Case;
use crate::support::{test_client_config, MiniTestnet, PointerSilence, CLIENT_NODE};
use ant_core::data::{Client, ClientConfig, Error, XorName};
use ant_node::storage::AntProtocol;
use ant_protocol::chunk::{
    ChunkMessage, ChunkMessageBody, PointerGetRequest, PointerGetResponse, PointerPutRequest,
    PointerPutResponse, ProtocolError,
};
use ant_protocol::evm::U256;
use ant_protocol::pointer::{
    pointer_address, Pointer, PointerTarget, PointerTargetKind, DATA_TYPE_POINTER, FINAL_COUNTER,
    POINTER_BODY_LEN, POINTER_WIRE_LEN,
};
use ant_protocol::pqc::api::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::{send_and_await_chunk_response, CLOSE_GROUP_SIZE};
use bytes::Bytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network(
            "pointer::a_pointer_is_created_paid_for_and_read_back",
            a_pointer_is_created_paid_for_and_read_back,
        ),
        Case::on_network(
            "pointer::an_update_is_paid_for_and_replaces_what_the_network_serves",
            an_update_is_paid_for_and_replaces_what_the_network_serves,
        ),
        Case::on_network(
            "pointer::every_node_accepts_a_paid_update",
            every_node_accepts_a_paid_update,
        ),
        Case::on_network(
            "pointer::a_write_that_fails_leaves_a_fork_that_the_next_counter_heals",
            a_write_that_fails_leaves_a_fork_that_the_next_counter_heals,
        ),
        Case::on_network(
            "pointer::a_node_refuses_unpaid_forged_and_misdirected_writes_over_the_network",
            a_node_refuses_unpaid_forged_and_misdirected_writes_over_the_network,
        ),
        Case::on_network(
            "pointer::creating_a_pointer_that_exists_is_refused_before_paying",
            creating_a_pointer_that_exists_is_refused_before_paying,
        ),
        Case::on_network(
            "pointer::a_chain_of_pointers_resolves_to_the_chunk_at_its_end",
            a_chain_of_pointers_resolves_to_the_chunk_at_its_end,
        ),
        Case::on_network(
            "pointer::a_read_asks_bootstrap_peers_by_peer_id",
            a_read_asks_bootstrap_peers_by_peer_id,
        ),
        Case::on_network(
            "pointer::a_transfer_hands_the_address_over_for_good",
            a_transfer_hands_the_address_over_for_good,
        ),
        Case::on_network(
            "pointer::a_final_state_left_on_one_node_refuses_a_second_transfer_before_paying",
            a_final_state_left_on_one_node_refuses_a_second_transfer_before_paying,
        ),
    ]
}

/// How long a reader waits for one peer's answer to a pointer GET in the
/// cases that silence peers: well past what an answering peer takes, so
/// those cases don't wait out the default for each silent one.
const SILENCED_READ_TIMEOUT_SECS: u64 = 5;

/// The client the cases use, once the testnet has converged.
async fn setup(testnet: &MiniTestnet) -> Client {
    // The harness waits for convergence but carries on if it runs out of
    // time. These tests address close groups by name, so an unconverged
    // network would fail them in confusing ways; say so here instead.
    let peers = testnet.running_node_count() - 1;
    for (index, node) in testnet.nodes.iter().enumerate() {
        let known = node.p2p_node.dht().get_routing_table_size().await;
        assert!(
            known >= peers,
            "the testnet did not converge: node {index} knows {known} of {peers} peers"
        );
    }
    testnet.client()
}

/// A fresh owner. Every test needs its own: the address *is* the key, so two
/// tests sharing one would be writing to one pointer.
fn owner() -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65()
        .generate_keypair()
        .expect("generate ML-DSA-65 keypair")
}

fn chunk_target(byte: u8) -> PointerTarget {
    PointerTarget::new(PointerTargetKind::Chunk, [byte; 32])
}

/// One peer of a close group, as the client addresses it and as the node
/// that runs it.
struct Member {
    peer_id: PeerId,
    addrs: Vec<MultiAddr>,
    protocol: Arc<AntProtocol>,
    silence: Arc<PointerSilence>,
}

/// The close group the client writes `address` to, found by the lookup the
/// client itself uses.
async fn close_group(client: &Client, testnet: &MiniTestnet, address: &XorName) -> Vec<Member> {
    let peers = client
        .network()
        .find_closest_peers(address, CLOSE_GROUP_SIZE)
        .await
        .expect("close group lookup");
    let group: Vec<Member> = peers
        .into_iter()
        .filter_map(|(peer_id, addrs)| {
            testnet.running().find_map(|node| {
                if *node.p2p_node.peer_id() != peer_id {
                    return None;
                }
                Some(Member {
                    peer_id,
                    addrs: addrs.clone(),
                    protocol: Arc::clone(&node.protocol),
                    silence: Arc::clone(&node.pointer_silence),
                })
            })
        })
        .collect();
    assert_eq!(
        group.len(),
        CLOSE_GROUP_SIZE,
        "every close-group peer is a testnet node"
    );
    group
}

/// Fail if the lookup no longer returns `group`, so a test that placed states
/// on named peers never reads from a different set without saying so.
///
/// The lookup keeps only peers that answer it in time, so one slow peer can
/// drop out of a single lookup without the group having moved. It is asked a
/// few times before the group is declared moved.
async fn assert_group_unchanged(client: &Client, address: &XorName, group: &[Member]) {
    let mut before: Vec<[u8; 32]> = group.iter().map(|m| *m.peer_id.as_bytes()).collect();
    before.sort_unstable();
    let mut now = Vec::new();
    for _ in 0..3 {
        now = client
            .network()
            .find_closest_peers(address, CLOSE_GROUP_SIZE)
            .await
            .expect("close group lookup")
            .iter()
            .map(|(peer_id, _)| *peer_id.as_bytes())
            .collect();
        now.sort_unstable();
        if now == before {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(now, before, "the close group moved during the test");
}

async fn balance(client: &Client) -> U256 {
    client
        .wallet()
        .expect("wallet")
        .balance_of_tokens()
        .await
        .expect("balance query")
}

/// Pay for `record`'s state once, the way the client does, and build the PUT
/// that carries the proof.
async fn paid(client: &Client, record: &Pointer) -> PointerPutRequest {
    let (proof, _) = client
        .pay_for_storage_split(
            &record.address(),
            &record.state_id(),
            POINTER_WIRE_LEN as u64,
            DATA_TYPE_POINTER,
        )
        .await
        .expect("pay for the pointer state");
    PointerPutRequest::with_payment(Bytes::from(record.to_bytes()), proof)
}

/// Send `request` to one close-group peer over QUIC from the client's node,
/// and return exactly what that peer answered.
async fn put_over_quic(
    client: &Client,
    member: &Member,
    request: PointerPutRequest,
) -> PointerPutResponse {
    static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1 << 62);
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::PointerPutRequest(request),
    };
    send_and_await_chunk_response(
        client.network().node(),
        &member.peer_id,
        message.encode().expect("encode"),
        request_id,
        Duration::from_secs(30),
        &member.addrs,
        |body| match body {
            ChunkMessageBody::PointerPutResponse(response) => Some(Ok(response)),
            _ => None,
        },
        |e| format!("pointer PUT send failed: {e}"),
        || "pointer PUT timed out".to_string(),
    )
    .await
    .expect("the peer answers a pointer PUT")
}

/// Hand `request` to one node's request handler and return its answer.
async fn put_to(node: &AntProtocol, request: &PointerPutRequest) -> PointerPutResponse {
    let message = ChunkMessage {
        request_id: 1,
        body: ChunkMessageBody::PointerPutRequest(request.clone()),
    };
    let reply = node
        .try_handle_request(&message.encode().expect("encode"))
        .await
        .expect("handle")
        .expect("a pointer PUT is answered");
    match ChunkMessage::decode(&reply).expect("decode").body {
        ChunkMessageBody::PointerPutResponse(response) => response,
        other => panic!("expected a pointer PUT response, got {other:?}"),
    }
}

/// What one node serves at `address`.
async fn held_by(node: &AntProtocol, address: &XorName) -> Option<Pointer> {
    let message = ChunkMessage {
        request_id: 2,
        body: ChunkMessageBody::PointerGetRequest(PointerGetRequest::new(*address)),
    };
    let reply = node
        .try_handle_request(&message.encode().expect("encode"))
        .await
        .expect("handle")
        .expect("a pointer GET is answered");
    match ChunkMessage::decode(&reply).expect("decode").body {
        ChunkMessageBody::PointerGetResponse(PointerGetResponse::Success { record }) => {
            Some(Pointer::from_bytes(&record).expect("a served record verifies"))
        }
        ChunkMessageBody::PointerGetResponse(PointerGetResponse::NotFound { .. }) => None,
        other => panic!("expected a pointer GET response, got {other:?}"),
    }
}

/// Pay for `record` once and deliver it to each of `members`, requiring every
/// one to store it.
async fn store_on(client: &Client, members: &[Member], record: &Pointer) {
    let request = paid(client, record).await;
    for (index, member) in members.iter().enumerate() {
        match put_to(&member.protocol, &request).await {
            PointerPutResponse::Success { address, state_id } => {
                assert_eq!(address, record.address());
                assert_eq!(state_id, record.state_id());
            }
            other => panic!(
                "member {index} refused a paid state at counter {}: {other:?}",
                record.counter()
            ),
        }
    }
}

/// Require each of `members` to serve exactly `record`'s state.
async fn assert_held(members: &[Member], record: &Pointer) {
    for (index, member) in members.iter().enumerate() {
        let held = held_by(&member.protocol, &record.address())
            .await
            .unwrap_or_else(|| panic!("member {index} holds nothing"));
        assert_eq!(
            held.state_id(),
            record.state_id(),
            "member {index} holds counter {} instead of counter {}",
            held.counter(),
            record.counter()
        );
    }
}

/// How many nodes anywhere in the testnet serve exactly `record`'s state.
async fn holders_anywhere(testnet: &MiniTestnet, record: &Pointer) -> usize {
    let mut count = 0;
    for protocol in testnet.running().map(|node| &node.protocol) {
        if held_by(protocol, &record.address())
            .await
            .is_some_and(|held| held.state_id() == record.state_id())
        {
            count += 1;
        }
    }
    count
}

/// A kind of pointer request a node can be told to ignore.
#[derive(Clone, Copy)]
enum Request {
    Get,
    Put,
}

/// Make every node in the testnet except `answering` ignore pointer requests
/// of `kind`, and `answering` handle them.
fn only_these_answer(testnet: &MiniTestnet, answering: &[Member], kind: Request) {
    for node in &testnet.nodes {
        let silent = !answering
            .iter()
            .any(|member| Arc::ptr_eq(&member.silence, &node.pointer_silence));
        let switch = match kind {
            Request::Get => &node.pointer_silence.gets,
            Request::Put => &node.pointer_silence.puts,
        };
        switch.store(silent, Ordering::Relaxed);
    }
}

/// Let every node handle every pointer request again.
fn everyone_answers(testnet: &MiniTestnet) {
    for node in &testnet.nodes {
        node.pointer_silence.gets.store(false, Ordering::Relaxed);
        node.pointer_silence.puts.store(false, Ordering::Relaxed);
    }
}

/// Read `address` while only `answering` handle pointer GETs.
///
/// The client's own lookup can leave out a peer that was meant to answer when
/// that peer is slow to answer the lookup itself; the read then hears from
/// fewer peers than were allowed, for a reason that has nothing to do with the
/// read. That one outcome is retried, a few times. Everything else — a value,
/// a shortfall with as many answers as were allowed, a failure to corroborate —
/// is returned at once, so no result under test is ever retried away.
async fn read_answered_by(
    reader: &Client,
    testnet: &MiniTestnet,
    address: &XorName,
    answering: &[Member],
) -> Result<Option<Pointer>, Error> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        only_these_answer(testnet, answering, Request::Get);
        let read = reader.pointer_get(address).await;
        everyone_answers(testnet);
        let heard_from_fewer = matches!(
            &read,
            Err(Error::CloseGroupShortfall(message))
                if message.contains("of the close group answered")
                    && number_after(message, "only ")
                        .is_some_and(|answered| answered < answering.len())
        );
        if !heard_from_fewer || attempts == 3 {
            return read;
        }
    }
}

/// The number written straight after `prefix` in `message`.
fn number_after(message: &str, prefix: &str) -> Option<usize> {
    message
        .split_once(prefix)?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

async fn a_pointer_is_created_paid_for_and_read_back(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();

    let before = balance(&client).await;
    let address = client
        .pointer_create(&sk, &pk, chunk_target(1))
        .await
        .expect("pointer_create should succeed with payment");
    assert!(
        balance(&client).await < before,
        "creating a pointer must settle a payment on chain"
    );

    // Public-key addressed: the client knew the address before it asked anyone.
    assert_eq!(address, pointer_address(&pk));

    let record = client
        .pointer_get(&address)
        .await
        .expect("pointer_get should succeed")
        .expect("the pointer must be found after creating it");

    assert_eq!(record.counter(), 0, "a create is counter 0");
    assert_eq!(record.target(), chunk_target(1));
    assert_eq!(record.address(), address);
    assert_eq!(
        record.owner().to_bytes(),
        pk.to_bytes(),
        "the record carries its own owner key"
    );
}

/// Pay to update: each update is its own paid state, and the network serves
/// the new one.
async fn an_update_is_paid_for_and_replaces_what_the_network_serves(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();

    let address = client
        .pointer_create(&sk, &pk, chunk_target(1))
        .await
        .expect("create");

    for expected_counter in 1..=2u64 {
        let before = balance(&client).await;
        let updated = client
            .pointer_update(&sk, &pk, chunk_target(expected_counter as u8 + 1))
            .await
            .expect("pointer_update should succeed with payment");
        assert_eq!(updated, address, "an update stays at the same address");
        assert!(
            balance(&client).await < before,
            "every update must settle a payment of its own"
        );

        let record = client
            .pointer_get(&address)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(
            record.counter(),
            expected_counter,
            "pointer_update signs one past what the network serves"
        );
        assert_eq!(record.target(), chunk_target(expected_counter as u8 + 1));
    }
}

/// Paid updates are accepted wherever they land.
///
/// A node that already holds a pointer takes a paid update to it, even one
/// that skips counters: the chunk path answers "already exists" and stops; a
/// pointer must not, or every update after the first is lost. Checked on
/// every node of the close group, not just a quorum, then through the
/// client's own update path.
///
/// The counter orders states; it does not meter them. A paid record that
/// skips counters is taken, and the client's next update carries on from it.
///
/// A write ends once its quorum has answered, so a node can miss updates. The
/// next update brings it level, however far behind it was.
async fn every_node_accepts_a_paid_update(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;

    // Every close-group node takes a paid update to a pointer it holds.
    let (pk, sk) = owner();
    let address = pointer_address(&pk);
    let group = close_group(&client, &testnet, &address).await;

    let created = Pointer::create(&sk, &pk, chunk_target(1)).expect("sign");
    store_on(&client, &group, &created).await;
    assert_held(&group, &created).await;

    // Every node holds the pointer now, and every one must take the update.
    let updated = Pointer::sign(&sk, &pk, 5, chunk_target(2)).expect("sign");
    store_on(&client, &group, &updated).await;
    assert_held(&group, &updated).await;

    // The same through the client's own path.
    assert_group_unchanged(&client, &address, &group).await;
    client
        .pointer_update(&sk, &pk, chunk_target(3))
        .await
        .expect("pointer_update with payment must not be refused");
    let record = client
        .pointer_get(&address)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(record.counter(), 6);
    assert_eq!(record.target(), chunk_target(3));

    // A paid update through the client may skip counters.
    let (pk, sk) = owner();
    let address = client
        .pointer_create(&sk, &pk, chunk_target(1))
        .await
        .expect("create");

    let skipped = Pointer::sign(&sk, &pk, 9, chunk_target(2)).expect("sign");
    client
        .pointer_put(&skipped)
        .await
        .expect("a paid record that skips counters must be taken");
    let held = client
        .pointer_get(&address)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(held.counter(), 9);
    assert_eq!(held.target(), chunk_target(2));

    client
        .pointer_update(&sk, &pk, chunk_target(3))
        .await
        .expect("an update after a skip");
    let held = client
        .pointer_get(&address)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(held.counter(), 10);
    assert_eq!(held.target(), chunk_target(3));

    // Nodes that missed updates take the next one.
    let (pk, sk) = owner();
    let address = pointer_address(&pk);
    let group = close_group(&client, &testnet, &address).await;
    let (current, lagging) = group.split_at_checked(5).expect("a full close group");

    let created = Pointer::create(&sk, &pk, chunk_target(1)).expect("sign");
    store_on(&client, &group, &created).await;

    // Two updates reach only five nodes; the same two nodes miss both.
    let first = created.update(&sk, chunk_target(2)).expect("sign");
    store_on(&client, current, &first).await;
    let second = first.update(&sk, chunk_target(3)).expect("sign");
    store_on(&client, current, &second).await;
    assert_held(current, &second).await;
    assert_held(lagging, &created).await;

    // Five nodes back the current state, so any four answers include two of
    // them and the network reads it.
    assert_group_unchanged(&client, &address, &group).await;
    let read = client
        .pointer_get(&address)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(read.state_id(), second.state_id());

    // The next update is three counters ahead of what the laggards hold, and
    // every node takes it, the laggards included.
    let next = second.update(&sk, chunk_target(4)).expect("sign");
    store_on(&client, &group, &next).await;
    assert_held(&group, &next).await;
}

/// A write that fails leaves a fork. Every node holds one state at counter 1;
/// the owner's competing write, which wins the merge, can reach only three of
/// the close group because every other node ignores it, so `pointer_put`
/// reports the shortfall — and the nodes it reached keep it. A read of four
/// answers can see either side corroborated, so it returns one of the two,
/// both owner-signed and paid for. The next update heals the fork on every
/// node.
async fn a_write_that_fails_leaves_a_fork_that_the_next_counter_heals(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();
    let address = pointer_address(&pk);
    let group = close_group(&client, &testnet, &address).await;
    // The closest three, never the member at the edge of the group.
    let reached = group.get(..3).expect("a full close group");

    let created = Pointer::create(&sk, &pk, chunk_target(1)).expect("sign");
    store_on(&client, &group, &created).await;
    let loser = Pointer::sign(&sk, &pk, 1, chunk_target(9)).expect("sign");
    store_on(&client, &group, &loser).await;

    let winner = Pointer::sign(&sk, &pk, 1, chunk_target(2)).expect("sign");
    assert!(winner.replaces(&loser), "smaller target bytes win");
    assert_group_unchanged(&client, &address, &group).await;
    only_these_answer(&testnet, reached, Request::Put);
    let written = client.pointer_put(&winner).await;
    // Taken while everyone else is still silent, so nothing in flight can
    // change it.
    let winner_holders = holders_anywhere(&testnet, &winner).await;
    everyone_answers(&testnet);

    let acknowledged = match &written {
        Err(Error::CloseGroupShortfall(message)) if message.contains("of 5 close-group peers") => {
            number_after(message, "stored on ")
        }
        _ => None,
    }
    .unwrap_or_else(|| panic!("a write that reaches three of seven must fail, got {written:?}"));
    assert_eq!(
        acknowledged, winner_holders,
        "the write counts exactly the replicas it left"
    );
    assert!(
        (1..=3).contains(&winner_holders),
        "a failed write lands where it reached and nowhere else, got {winner_holders} replicas"
    );

    // It failed, and it still landed where it reached: a fork.
    for (index, member) in group.iter().enumerate() {
        let held = held_by(&member.protocol, &address)
            .await
            .unwrap_or_else(|| panic!("member {index} holds nothing"));
        assert!(
            held.state_id() == winner.state_id() || held.state_id() == loser.state_id(),
            "member {index} holds neither side of the fork"
        );
    }

    assert_group_unchanged(&client, &address, &group).await;
    let read = client
        .pointer_get(&address)
        .await
        .expect("a forked pointer still reads")
        .expect("present");
    assert!(
        read.state_id() == winner.state_id() || read.state_id() == loser.state_id(),
        "a forked read returns one of the two corroborated states"
    );
    assert_eq!(read.counter(), 1);

    // The owner updates as usual, one past what the read returned. Every node
    // on either side takes it, so it reaches the write quorum.
    client
        .pointer_update(&sk, &pk, chunk_target(5))
        .await
        .expect("an update must heal a fork");
    let healed = client
        .pointer_get(&address)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(healed.counter(), 2);
    assert_eq!(healed.target(), chunk_target(5));

    // The write stopped at its quorum. Delivering the same state to the whole
    // group shows that no node on either side refuses it: each either already
    // holds it or takes it now.
    let request = paid(&client, &healed).await;
    for (index, member) in group.iter().enumerate() {
        match put_to(&member.protocol, &request).await {
            PointerPutResponse::Success { state_id, .. }
            | PointerPutResponse::Unchanged { state_id, .. } => {
                assert_eq!(state_id, healed.state_id(), "member {index}");
            }
            other => panic!("member {index} refused the healing update: {other:?}"),
        }
    }
    assert_held(&group, &healed).await;
}

/// Over QUIC, from the client's node to one close-group peer: an unpaid record
/// is refused, a forged one is refused, a proof paid for a different state is
/// refused, and only the genuine record paid for itself is stored.
async fn a_node_refuses_unpaid_forged_and_misdirected_writes_over_the_network(
    testnet: Arc<MiniTestnet>,
) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();
    let address = pointer_address(&pk);
    let group = close_group(&client, &testnet, &address).await;
    let peer = group.first().expect("a close-group peer");

    let created = Pointer::create(&sk, &pk, chunk_target(1)).expect("sign");

    // No proof at all.
    let unpaid = PointerPutRequest::new(Bytes::from(created.to_bytes()));
    match put_over_quic(&client, peer, unpaid).await {
        PointerPutResponse::PaymentRequired { .. } => {}
        other => panic!("an unpaid record must be refused, got {other:?}"),
    }
    assert!(held_by(&peer.protocol, &address).await.is_none());

    // A real payment for this state, carried by a record whose signature is
    // broken. The body is untouched, so the state and the payment match.
    let genuine = paid(&client, &created).await;
    let proof = genuine.payment_proof.clone().expect("a paid request");
    let mut forged_bytes = created.to_bytes();
    if let Some(byte) = forged_bytes.get_mut(POINTER_BODY_LEN) {
        *byte ^= 0x01;
    }
    let forged = PointerPutRequest::with_payment(Bytes::from(forged_bytes), proof.clone());
    match put_over_quic(&client, peer, forged).await {
        PointerPutResponse::Error(ProtocolError::StorageFailed(message))
            if message.contains("signature") => {}
        other => panic!("a forged record must be refused for its signature, got {other:?}"),
    }
    assert!(held_by(&peer.protocol, &address).await.is_none());

    // The genuine record with its own payment.
    match put_over_quic(&client, peer, genuine).await {
        PointerPutResponse::Success {
            address: at,
            state_id,
        } => {
            assert_eq!(at, address);
            assert_eq!(state_id, created.state_id());
        }
        other => panic!("a paid genuine record must be stored, got {other:?}"),
    }
    assert_held(std::slice::from_ref(peer), &created).await;

    // An update carrying the create's payment: paid, but for another state.
    let update = created.update(&sk, chunk_target(2)).expect("sign");
    let misdirected = PointerPutRequest::with_payment(Bytes::from(update.to_bytes()), proof);
    match put_over_quic(&client, peer, misdirected).await {
        PointerPutResponse::PaymentRequired { .. } => {}
        other => panic!("a payment for another state must be refused, got {other:?}"),
    }
    assert_held(std::slice::from_ref(peer), &created).await;

    // The same update paid for itself is taken.
    match put_over_quic(&client, peer, paid(&client, &update).await).await {
        PointerPutResponse::Success { state_id, .. } => assert_eq!(state_id, update.state_id()),
        other => panic!("a paid update must be stored, got {other:?}"),
    }
    assert_held(std::slice::from_ref(peer), &update).await;
}

/// Creating a pointer that already exists is refused before anything is
/// paid: the payment would buy nothing, whatever state the network holds.
async fn creating_a_pointer_that_exists_is_refused_before_paying(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();
    client
        .pointer_create(&sk, &pk, chunk_target(1))
        .await
        .expect("create");

    let before = balance(&client).await;
    let err = client
        .pointer_create(&sk, &pk, chunk_target(2))
        .await
        .expect_err("a second create must be refused");
    assert!(err.to_string().contains("already exists"), "got: {err}");
    assert_eq!(balance(&client).await, before, "the refused create paid");
}

/// A pointer may target another pointer. Resolution walks the chain client-side
/// — the node never reads a target — and ends at the chunk.
async fn a_chain_of_pointers_resolves_to_the_chunk_at_its_end(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;
    let (last_pk, last_sk) = owner();
    let (first_pk, first_sk) = owner();

    let content = Bytes::from("the chunk a pointer chain ends at");
    let chunk = client.chunk_put(content.clone()).await.expect("chunk_put");

    // The end of the chain points at the chunk.
    let last = client
        .pointer_create(
            &last_sk,
            &last_pk,
            PointerTarget::new(PointerTargetKind::Chunk, chunk),
        )
        .await
        .expect("create the last hop");

    // The head points at that pointer.
    let first = client
        .pointer_create(
            &first_sk,
            &first_pk,
            PointerTarget::new(PointerTargetKind::Pointer, last),
        )
        .await
        .expect("create the first hop");

    let resolved = client
        .pointer_resolve(&first)
        .await
        .expect("the chain must resolve");
    assert_eq!(resolved.kind(), Some(PointerTargetKind::Chunk));
    assert_eq!(resolved.address, chunk);

    let fetched = client
        .chunk_get(&resolved.address)
        .await
        .expect("chunk_get")
        .expect("the chunk the chain names must be there");
    assert_eq!(fetched.content.as_ref(), content.as_ref());
}

/// Bootstrap peers named by `/p2p/` address are read directly. Two members
/// of the close group are a reader's bootstrap peers and only they answer
/// pointer GETs: a read of the close group alone falls short, and one that
/// also asks the bootstrap peers returns the state, whether they were given to
/// a client built on a node or are the seeds it connected through.
async fn a_read_asks_bootstrap_peers_by_peer_id(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();
    let address = client
        .pointer_create(&sk, &pk, chunk_target(1))
        .await
        .expect("create");
    let group = close_group(&client, &testnet, &address).await;
    let (answering, _) = group.split_at_checked(2).expect("a full close group");
    let config = ClientConfig {
        chunk_get_timeout_secs: SILENCED_READ_TIMEOUT_SECS,
        ..test_client_config()
    };
    let reader = Client::from_node(
        testnet.node(CLIENT_NODE).expect("client node"),
        config.clone(),
    );
    let seeds: Vec<MultiAddr> = answering
        .iter()
        .flat_map(|member| {
            member
                .addrs
                .iter()
                .map(|addr| addr.clone().with_peer_id(member.peer_id))
        })
        .collect();

    let read = read_answered_by(&reader, &testnet, &address, answering).await;
    assert!(
        matches!(&read, Err(Error::CloseGroupShortfall(message))
            if message.contains("only 2 of the close group answered")),
        "two answers are not a quorum of the close group: {read:?}"
    );

    let node = testnet.node(CLIENT_NODE).expect("client node");
    let given = Client::from_node(node, config.clone()).with_bootstrap_peers(&seeds);
    let connected = Client::connect_multiaddrs(
        &seeds,
        ClientConfig {
            allow_loopback: true,
            ipv6: false,
            ..config
        },
    )
    .await
    .expect("connect through the seeds");
    for reader in [&given, &connected] {
        let read = read_answered_by(reader, &testnet, &address, answering)
            .await
            .expect("the bootstrap peers answer")
            .expect("present");
        assert_eq!(read.address(), address);
        assert_eq!(read.counter(), 0);
    }

    drop(connected);
    drop(given);
}

/// A transfer hands the address over for good (ADR-0018 in `ant-node`).
///
/// Refused before anything is paid when it could not land well: to the
/// pointer itself, to a pointer nobody created, or to one that leads back.
/// Once stored, readers of the address are redirected to the recipient's
/// pointer, which the recipient moves, and the former owner can move nothing:
/// the client refuses before paying, and a paid final state sent straight to
/// every node that holds the transfer is refused by each, whichever way its
/// target sorts.
async fn a_transfer_hands_the_address_over_for_good(testnet: Arc<MiniTestnet>) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();
    let (recipient_pk, recipient_sk) = owner();

    let address = client
        .pointer_create(&sk, &pk, chunk_target(1))
        .await
        .expect("create the pointer to hand over");
    let recipient = client
        .pointer_create(&recipient_sk, &recipient_pk, chunk_target(2))
        .await
        .expect("the recipient creates its own pointer");

    // Refusals that cost nothing.
    let before = balance(&client).await;
    let to_itself = client.pointer_transfer(&sk, &pk, address).await;
    assert!(matches!(to_itself, Err(Error::InvalidData(ref m)) if m.contains("itself")));
    let nowhere = client.pointer_transfer(&sk, &pk, [0x42; 32]).await;
    assert!(matches!(nowhere, Err(Error::InvalidData(ref m)) if m.contains("does not exist")));
    let (loop_pk, loop_sk) = owner();
    let loops_back = client
        .pointer_create(
            &loop_sk,
            &loop_pk,
            PointerTarget::new(PointerTargetKind::Pointer, address),
        )
        .await
        .expect("a pointer that forwards back to the one being handed over");
    let paid_for_loop = balance(&client).await;
    let cycle = client.pointer_transfer(&sk, &pk, loops_back).await;
    assert!(matches!(cycle, Err(Error::InvalidData(ref m)) if m.contains("cycle")));
    assert!(
        before > paid_for_loop,
        "only the forwarding pointer was paid for"
    );
    assert_eq!(
        balance(&client).await,
        paid_for_loop,
        "no refused transfer settles a payment"
    );

    // The transfer itself.
    let transfer = client
        .pointer_transfer(&sk, &pk, recipient)
        .await
        .expect("the transfer lands");
    assert!(
        balance(&client).await < paid_for_loop,
        "a transfer is paid for"
    );
    assert_eq!(transfer.address, address);
    let finality = transfer.finality.expect("the group can be asked");
    assert_eq!(finality.address, address);
    assert!(finality.is_final(), "got {:?}", finality.status);
    assert_eq!(finality.transferred_to(), Some(recipient));

    let held = client
        .pointer_get(&address)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(held.counter(), FINAL_COUNTER);
    assert_eq!(held.transferred_to(), Some(recipient));

    // Readers follow it; the recipient moves it.
    assert_eq!(
        client.pointer_resolve(&address).await.expect("resolve"),
        chunk_target(2)
    );
    client
        .pointer_update(&recipient_sk, &recipient_pk, chunk_target(3))
        .await
        .expect("the recipient updates its own pointer");
    assert_eq!(
        client.pointer_resolve(&address).await.expect("resolve"),
        chunk_target(3),
        "the recipient now decides what the address resolves to"
    );
    let controller = client
        .pointer_controller(&address)
        .await
        .expect("controller");
    assert_eq!(controller.pointer, recipient);
    assert_eq!(controller.transfers, vec![recipient]);
    assert!(!controller.frozen);

    // The former owner, through the client: refused before paying.
    let before = balance(&client).await;
    let update = client.pointer_update(&sk, &pk, chunk_target(4)).await;
    assert!(
        matches!(update, Err(Error::PointerFinal(_))),
        "got {update:?}"
    );
    let again = client.pointer_transfer(&sk, &pk, loops_back).await;
    assert!(
        matches!(again, Err(Error::PointerFinal(_))),
        "got {again:?}"
    );
    assert_eq!(balance(&client).await, before, "nothing was paid");

    // The former owner, around the client: a paid final state whose target
    // sorts first, sent to every node that holds the transfer.
    let group = close_group(&client, &testnet, &address).await;
    let take_back = Pointer::sign(
        &sk,
        &pk,
        FINAL_COUNTER,
        PointerTarget::new(PointerTargetKind::Chunk, [0; 32]),
    )
    .expect("sign");
    assert!(take_back.target().to_bytes() < held.target().to_bytes());
    let request = paid(&client, &take_back).await;
    let mut refused = 0;
    for member in &group {
        let holds_transfer = held_by(&member.protocol, &address)
            .await
            .is_some_and(|record| record.state_id() == held.state_id());
        if !holds_transfer {
            continue;
        }
        match put_over_quic(&client, member, request.clone()).await {
            PointerPutResponse::Stale { state_id, .. } => {
                assert_eq!(state_id, held.state_id(), "the refusal names the transfer");
                refused += 1;
            }
            other => panic!("a node holding the transfer took another final state: {other:?}"),
        }
    }
    assert!(
        refused >= 5,
        "the transfer reached a write quorum ({refused})"
    );
    assert_group_unchanged(&client, &address, &group).await;
    assert_eq!(
        client
            .pointer_get(&address)
            .await
            .expect("get")
            .expect("present")
            .state_id(),
        held.state_id()
    );
    assert!(client
        .pointer_finality(&address)
        .await
        .expect("finality")
        .is_final());
}

/// A transfer that fell short left its final state on one node. A read does
/// not return a state only one peer holds, so a second transfer built on a
/// read would sign past it, pay, and fork the pointer for good on the nodes
/// that never heard of the first. The whole group is asked first, and the
/// second transfer is refused before anything is paid.
async fn a_final_state_left_on_one_node_refuses_a_second_transfer_before_paying(
    testnet: Arc<MiniTestnet>,
) {
    let client = setup(&testnet).await;
    let (pk, sk) = owner();
    let (recipient_pk, recipient_sk) = owner();
    let address = client
        .pointer_create(&sk, &pk, chunk_target(1))
        .await
        .expect("create the pointer");
    let recipient = client
        .pointer_create(&recipient_sk, &recipient_pk, chunk_target(2))
        .await
        .expect("the recipient creates its own pointer");

    let group = close_group(&client, &testnet, &address).await;
    let first = Pointer::sign(
        &sk,
        &pk,
        FINAL_COUNTER,
        PointerTarget::new(PointerTargetKind::Pointer, [0x42; 32]),
    )
    .expect("sign");
    let (one, _) = group.split_at(1);
    store_on(&client, one, &first).await;
    assert_eq!(
        client
            .pointer_get(&address)
            .await
            .expect("get")
            .expect("present")
            .counter(),
        0,
        "a read does not return a state one node holds"
    );

    let before = balance(&client).await;
    let second = client.pointer_transfer(&sk, &pk, recipient).await;
    assert!(
        matches!(&second, Err(Error::PointerFinal(m)) if m.contains(&hex::encode(first.state_id()))),
        "got {second:?}"
    );
    assert_eq!(balance(&client).await, before, "nothing was paid");

    // Nor will the owner update past it: the node holding it would never
    // follow, so the group would split for good.
    let update = client.pointer_update(&sk, &pk, chunk_target(3)).await;
    assert!(
        matches!(&update, Err(Error::PointerFinal(m)) if m.contains(&hex::encode(first.state_id()))),
        "got {update:?}"
    );
    assert_eq!(
        balance(&client).await,
        before,
        "nothing was paid for the update"
    );
    assert_eq!(
        holders_anywhere(&testnet, &first).await,
        1,
        "and nothing else changed"
    );
}
