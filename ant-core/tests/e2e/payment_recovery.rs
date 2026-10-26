//! A record paid for on its own (a chunk put, a pointer write) recovers a
//! payment the RPC answered with an error, against real nodes and the DARWIN
//! vault's code on Anvil, and pays for it exactly once.
//!
//! The client's wallet reaches the chain through a JSON-RPC proxy that
//! forwards every call to Anvil. Armed, it forwards the next
//! `eth_sendRawTransaction`, so the payment is mined, and answers it with
//! `-32603`, as a public RPC sometimes does after taking a transaction. It can
//! also stop answering after that, so the check the client makes 10 seconds
//! later can't see the payment either: the attempt then fails with the
//! payment's journal kept on disk, and the same write run again by a new
//! client, as a new process would run it, finds the payment on the chain
//! instead of paying again. Each test counts the transactions the wallet sent
//! (its nonce, read from Anvil directly).
//!
//! Two small files uploaded at once from one wallet share one payment wave,
//! one transaction for both, and recover it the same way: each file's
//! records are charged once, in the first run and in a rerun from each
//! file's journal.
//!
//! A kept proof that every storer refuses (here, with every PUT of the
//! process answered as a node answers a proof it refuses) is paid again at
//! most once across runs, never when the run that refuses it settled it
//! from the journal, and never while the vault's record of its payment
//! can't be read.

use crate::support::runner::Case;
use crate::support::{test_client_config, MiniTestnet, CLIENT_NODE};
use alloy::providers::Provider;
use ant_core::data::{
    compute_address, ml_dsa_65, Client, Error, PaymentMode, PointerTarget, PointerTargetKind,
};
use ant_protocol::evm::{CustomNetwork, Network as EvmNetwork, Wallet, U256};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network(
            "payment_recovery::a_chunk_put_the_rpc_errored_on_pays_once",
            a_chunk_put_the_rpc_errored_on_pays_once,
        ),
        Case::on_network(
            "payment_recovery::a_pointer_write_the_rpc_errored_on_pays_once",
            a_pointer_write_the_rpc_errored_on_pays_once,
        ),
        Case::on_network(
            "payment_recovery::files_sharing_a_wave_the_rpc_errored_on_pay_once",
            files_sharing_a_wave_the_rpc_errored_on_pay_once,
        ),
        Case::on_network(
            "payment_recovery::a_payment_settled_from_the_journal_is_not_paid_again_when_refused",
            a_payment_settled_from_the_journal_is_not_paid_again_when_refused,
        ),
        Case::on_network(
            "payment_recovery::refusals_on_every_run_pay_again_at_most_once",
            refusals_on_every_run_pay_again_at_most_once,
        ),
        Case::on_network(
            "payment_recovery::a_failed_payment_after_a_refusal_never_pays_a_third_time",
            a_failed_payment_after_a_refusal_never_pays_a_third_time,
        ),
        Case::on_network(
            "payment_recovery::a_refused_proof_whose_payment_cant_be_read_is_kept",
            a_refused_proof_whose_payment_cant_be_read_is_kept,
        ),
    ]
}

/// What the proxy in front of Anvil does.
#[derive(Default)]
struct Proxy {
    /// Anvil's RPC URL.
    upstream: String,
    http: reqwest::Client,
    /// Forward the next `eth_sendRawTransaction` and answer it with -32603.
    fail_next_send: AtomicBool,
    /// After answering that one with -32603, answer every call so, and
    /// forward nothing, until [`Proxy::restore`].
    then_go_down: AtomicBool,
    down: AtomicBool,
    /// `eth_sendRawTransaction` calls forwarded.
    sends: AtomicUsize,
    /// Answer every `eth_estimateGas` with -32603, forwarding none, so a
    /// payment fails before anything is signed or sent.
    refuse_gas_estimates: AtomicBool,
}

impl Proxy {
    /// The RPC answers the next payment with an error after taking it, and
    /// answers again at once: the client's check 10 seconds later sees it.
    fn fail_next_send(&self) {
        self.fail_next_send.store(true, Ordering::SeqCst);
    }

    /// The RPC answers the next payment with an error after taking it, and
    /// then answers nothing but errors: the check sees nothing either.
    fn fail_next_send_then_go_down(&self) {
        self.then_go_down.store(true, Ordering::SeqCst);
        self.fail_next_send.store(true, Ordering::SeqCst);
    }

    /// The RPC answers again.
    fn restore(&self) {
        self.down.store(false, Ordering::SeqCst);
    }

    /// The RPC answers nothing but errors, until [`Proxy::restore`].
    fn go_down(&self) {
        self.down.store(true, Ordering::SeqCst);
    }

    /// Every payment fails before anything is signed or sent, while `on`.
    fn refuse_gas_estimates(&self, on: bool) {
        self.refuse_gas_estimates.store(on, Ordering::SeqCst);
    }

    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }
}

/// A JSON-RPC error answer, as a public RPC gives one.
fn internal_error(id: Value) -> Response {
    axum::Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32603, "message": "Internal error" },
    }))
    .into_response()
}

/// Relay one JSON-RPC call to Anvil, as the proxy is told to.
async fn relay(State(proxy): State<Arc<Proxy>>, body: axum::body::Bytes) -> Response {
    let call: Value = serde_json::from_slice(&body).unwrap_or_default();
    let id = call.get("id").cloned().unwrap_or(Value::Null);
    if proxy.down.load(Ordering::SeqCst) {
        return internal_error(id);
    }
    if proxy.refuse_gas_estimates.load(Ordering::SeqCst)
        && call.get("method").and_then(Value::as_str) == Some("eth_estimateGas")
    {
        return internal_error(id);
    }
    let send = call.get("method").and_then(Value::as_str) == Some("eth_sendRawTransaction");
    if send {
        proxy.sends.fetch_add(1, Ordering::SeqCst);
    }
    let answer = proxy
        .http
        .post(&proxy.upstream)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("Anvil answers")
        .bytes()
        .await
        .expect("Anvil's answer");
    if send && proxy.fail_next_send.swap(false, Ordering::SeqCst) {
        if proxy.then_go_down.swap(false, Ordering::SeqCst) {
            proxy.down.store(true, Ordering::SeqCst);
        }
        return internal_error(id);
    }
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        answer,
    )
        .into_response()
}

/// The proxy in front of the testnet's Anvil (the DARWIN vault's code), and
/// a funded wallet, as Anvil sees it directly and as the proxy shows it.
async fn setup(testnet: &MiniTestnet) -> (Arc<Proxy>, Wallet, Wallet) {
    let anvil = testnet.evm_network().clone();

    let proxy = Arc::new(Proxy {
        upstream: anvil.rpc_url().to_string(),
        ..Proxy::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let router = axum::Router::new()
        .route("/", axum::routing::post(relay))
        .with_state(Arc::clone(&proxy));
    tokio::spawn(async move { axum::serve(listener, router).await });
    let proxied = EvmNetwork::Custom(CustomNetwork {
        rpc_url_http: url.parse().unwrap(),
        payment_token_address: *anvil.payment_token_address(),
        payment_vault_address: *anvil.payment_vault_address(),
    });

    // A wallet of its own, so its nonce counts this test's payments only.
    let key = hex::encode(alloy::signers::local::PrivateKeySigner::random().to_bytes());
    let direct = Wallet::new_from_private_key(anvil.clone(), &key).unwrap();
    let funder = testnet.wallet();
    let tokens = funder.balance_of_tokens().await.unwrap() / U256::from(2);
    funder
        .transfer_tokens(direct.address(), tokens)
        .await
        .unwrap();
    funder
        .transfer_gas_tokens(direct.address(), U256::from(10u64.pow(18)))
        .await
        .unwrap();
    direct
        .approve_to_spend_tokens(*anvil.payment_vault_address(), U256::MAX)
        .await
        .unwrap();
    let proxied = Wallet::new_from_private_key(proxied, &key).unwrap();
    (proxy, direct, proxied)
}

/// A client paying through the proxy. Each attempt below takes a new one,
/// as a new run of a command would.
fn client(testnet: &MiniTestnet, wallet: &Wallet) -> Client {
    let node = testnet.node(CLIENT_NODE).expect("client node");
    Client::from_node(node, test_client_config()).with_wallet(wallet.clone())
}

/// The transactions the wallet has sent and its token balance, from Anvil.
async fn spent(wallet: &Wallet) -> (u64, U256) {
    let nonce = wallet
        .to_provider()
        .get_transaction_count(wallet.address())
        .await
        .unwrap();
    (nonce, wallet.balance_of_tokens().await.unwrap())
}

/// The payment checkpoints of records in the client's data directory.
fn record_checkpoints() -> usize {
    let directory: PathBuf = ant_core::config::data_dir()
        .unwrap()
        .join("payments/record");
    match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.path().extension().is_some_and(|e| e == "msgpack"))
            })
            .count(),
        Err(_) => 0,
    }
}

/// The checkpoints of file uploads in the client's data directory.
fn upload_checkpoints() -> usize {
    let directory: PathBuf = ant_core::config::data_dir()
        .unwrap()
        .join("payments/upload");
    match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.path().extension().is_some_and(|e| e == "msgpack"))
            })
            .count(),
        Err(_) => 0,
    }
}

/// A small file of random bytes: a few records, well under a wave.
fn random_file() -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let bytes = (0..4096).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
    file.write_all(&bytes).unwrap();
    file.flush().unwrap();
    file
}

fn random_chunk() -> Bytes {
    Bytes::from((0..1024).map(|_| rand::random::<u8>()).collect::<Vec<_>>())
}

/// Every chunk PUT of this process is answered as a proof refused, until
/// dropped.
struct Refusing;

impl Refusing {
    fn start() -> Self {
        Client::refuse_puts_as_unpaid(true);
        Self
    }
}

impl Drop for Refusing {
    fn drop(&mut self) {
        Client::refuse_puts_as_unpaid(false);
    }
}

/// The transactions the wallet has sent, from Anvil.
async fn sent(wallet: &Wallet) -> u64 {
    spent(wallet).await.0
}

/// `chunk_put` whose payment the RPC answered with an error pays once: in
/// one run when the chain shows the payment 10 seconds later, and across two
/// when it doesn't, the second run finding the journaled payment.
async fn a_chunk_put_the_rpc_errored_on_pays_once(testnet: Arc<MiniTestnet>) {
    let (proxy, direct, proxied) = setup(&testnet).await;
    let checkpoints = record_checkpoints();

    let content = random_chunk();
    let before = spent(&direct).await;
    proxy.fail_next_send();
    let address = client(&testnet, &proxied)
        .chunk_put(content.clone())
        .await
        .expect("the put finds its payment on the chain and stores the chunk");
    assert_eq!(address, compute_address(&content));
    let after = spent(&direct).await;
    assert_eq!(after.0, before.0 + 1, "exactly one transaction");
    assert!(after.1 < before.1, "and it paid");
    assert_eq!(proxy.sends(), 1);
    let read = client(&testnet, &proxied)
        .chunk_get(&address)
        .await
        .unwrap()
        .expect("the chunk is stored");
    assert_eq!(read.content, content);
    assert_eq!(
        record_checkpoints(),
        checkpoints,
        "nothing kept once stored"
    );

    let content = random_chunk();
    let before = spent(&direct).await;
    proxy.fail_next_send_then_go_down();
    let error = client(&testnet, &proxied)
        .chunk_put(content.clone())
        .await
        .expect_err("the payment's outcome can't be seen");
    assert!(matches!(error, Error::Payment(_)), "{error}");
    assert_eq!(spent(&direct).await.0, before.0 + 1, "the payment was sent");
    assert_eq!(record_checkpoints(), checkpoints + 1, "its journal is kept");
    proxy.restore();
    let address = client(&testnet, &proxied)
        .chunk_put(content.clone())
        .await
        .expect("the put run again finds the payment and stores the chunk");
    let after = spent(&direct).await;
    assert_eq!(
        after.0,
        before.0 + 1,
        "exactly one transaction across both runs"
    );
    assert!(after.1 < before.1, "and it paid");
    assert_eq!(proxy.sends(), 2, "the payment was sent once");
    let read = client(&testnet, &proxied)
        .chunk_get(&address)
        .await
        .unwrap()
        .expect("the chunk is stored");
    assert_eq!(read.content, content);
    assert_eq!(
        record_checkpoints(),
        checkpoints,
        "nothing kept once stored"
    );
}

/// A pointer write whose payment the RPC answered with an error pays once,
/// as a chunk put does: a create recovered in one run, and an update across
/// two, the second signing the same state and finding its payment.
async fn a_pointer_write_the_rpc_errored_on_pays_once(testnet: Arc<MiniTestnet>) {
    let (proxy, direct, proxied) = setup(&testnet).await;
    let checkpoints = record_checkpoints();
    let (owner, secret) = ml_dsa_65().generate_keypair().unwrap();
    let first = PointerTarget::new(PointerTargetKind::Chunk, [1; 32]);
    let second = PointerTarget::new(PointerTargetKind::Chunk, [2; 32]);

    let before = spent(&direct).await;
    proxy.fail_next_send();
    let address = client(&testnet, &proxied)
        .pointer_create(&secret, &owner, first)
        .await
        .expect("the create finds its payment on the chain and stores the pointer");
    let after = spent(&direct).await;
    assert_eq!(after.0, before.0 + 1, "exactly one transaction");
    assert!(after.1 < before.1, "and it paid");
    assert_eq!(proxy.sends(), 1);
    let read = client(&testnet, &proxied)
        .pointer_get(&address)
        .await
        .unwrap()
        .expect("the pointer is stored");
    assert_eq!((read.counter(), read.target()), (0, first));
    assert_eq!(
        record_checkpoints(),
        checkpoints,
        "nothing kept once stored"
    );

    let before = spent(&direct).await;
    proxy.fail_next_send_then_go_down();
    let error = client(&testnet, &proxied)
        .pointer_update(&secret, &owner, second)
        .await
        .expect_err("the payment's outcome can't be seen");
    assert!(matches!(error, Error::Payment(_)), "{error}");
    assert_eq!(spent(&direct).await.0, before.0 + 1, "the payment was sent");
    assert_eq!(record_checkpoints(), checkpoints + 1, "its journal is kept");
    proxy.restore();
    client(&testnet, &proxied)
        .pointer_update(&secret, &owner, second)
        .await
        .expect("the update run again finds the payment and stores the state");
    let after = spent(&direct).await;
    assert_eq!(
        after.0,
        before.0 + 1,
        "exactly one transaction across both runs"
    );
    assert!(after.1 < before.1, "and it paid");
    assert_eq!(proxy.sends(), 2, "the payment was sent once");
    let read = client(&testnet, &proxied)
        .pointer_get(&address)
        .await
        .unwrap()
        .expect("the pointer is stored");
    assert_eq!((read.counter(), read.target()), (1, second));
    assert_eq!(
        record_checkpoints(),
        checkpoints,
        "nothing kept once stored"
    );
}

/// Two small files uploaded at once share one payment wave. When the RPC
/// answers its transaction with an error and then stops answering, both
/// uploads fail with their journals kept, after one transaction; run again,
/// each finds the wave's payment from its own journal, with no new one.
/// Each file's records are charged once: the rerun takes the wave's receipt
/// only if each file's share is exactly its own quotes' total (the upload
/// checks it), and each envelope's payment record checks against the chain.
async fn files_sharing_a_wave_the_rpc_errored_on_pay_once(testnet: Arc<MiniTestnet>) {
    let (proxy, direct, proxied) = setup(&testnet).await;
    let checkpoints = upload_checkpoints();
    let (first, second) = (random_file(), random_file());

    let before = spent(&direct).await;
    proxy.fail_next_send_then_go_down();
    let sharing = client(&testnet, &proxied);
    // Both uploads join one wave whatever their timing.
    sharing.set_shared_wave_wait(Duration::from_secs(120));
    let (a, b) = tokio::join!(
        sharing.file_upload_with_mode(first.path(), PaymentMode::Single),
        sharing.file_upload_with_mode(second.path(), PaymentMode::Single),
    );
    assert!(a.is_err() && b.is_err(), "the wave's outcome can't be seen");
    drop(sharing);
    assert_eq!(
        spent(&direct).await.0,
        before.0 + 1,
        "one transaction for both files"
    );
    assert_eq!(proxy.sends(), 1);
    assert_eq!(
        upload_checkpoints(),
        checkpoints + 2,
        "each file's journal is kept"
    );
    proxy.restore();

    for file in [&first, &second] {
        let result = client(&testnet, &proxied)
            .file_upload_with_mode(file.path(), PaymentMode::Single)
            .await
            .expect("the upload run again finds the wave's payment and stores the file");
        let envelope = result.envelope.expect("the file's envelope");
        assert!(envelope.proof_checked, "{:?}", envelope.proof_problem);
        let output = tempfile::TempDir::new().unwrap();
        let path = output.path().join("read");
        client(&testnet, &proxied)
            .file_download(&result.data_map, &path)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(path).unwrap(),
            std::fs::read(file.path()).unwrap()
        );
    }
    let after = spent(&direct).await;
    assert_eq!(
        after.0,
        before.0 + 1,
        "exactly one transaction across both runs"
    );
    assert!(after.1 < before.1, "and it paid");
    assert_eq!(
        upload_checkpoints(),
        checkpoints,
        "nothing kept once stored"
    );
}

/// A payment a run left journaled, settled by the next run, whose storers
/// all refuse its proof in that run, is not paid for again: the refusal is
/// a failure, the proof kept, and a later run stores the record with it.
/// For a chunk put and for a file upload.
async fn a_payment_settled_from_the_journal_is_not_paid_again_when_refused(
    testnet: Arc<MiniTestnet>,
) {
    let (proxy, direct, proxied) = setup(&testnet).await;
    let checkpoints = (record_checkpoints(), upload_checkpoints());

    let content = random_chunk();
    let before = sent(&direct).await;
    proxy.fail_next_send_then_go_down();
    client(&testnet, &proxied)
        .chunk_put(content.clone())
        .await
        .expect_err("the payment's outcome can't be seen");
    proxy.restore();
    {
        let _refusing = Refusing::start();
        client(&testnet, &proxied)
            .chunk_put(content.clone())
            .await
            .expect_err("every storer refuses the settled proof");
    }
    assert_eq!(
        sent(&direct).await,
        before + 1,
        "the payment settled from the journal is not paid again"
    );
    client(&testnet, &proxied)
        .chunk_put(content.clone())
        .await
        .expect("stored with the settled proof");
    assert_eq!(sent(&direct).await, before + 1, "one transaction in all");

    let file = random_file();
    let before = sent(&direct).await;
    proxy.fail_next_send_then_go_down();
    client(&testnet, &proxied)
        .file_upload_with_mode(file.path(), PaymentMode::Single)
        .await
        .expect_err("the payment's outcome can't be seen");
    proxy.restore();
    {
        let _refusing = Refusing::start();
        client(&testnet, &proxied)
            .file_upload_with_mode(file.path(), PaymentMode::Single)
            .await
            .expect_err("every storer refuses the settled proofs");
    }
    assert_eq!(
        sent(&direct).await,
        before + 1,
        "the payment settled from the journal is not paid again"
    );
    client(&testnet, &proxied)
        .file_upload_with_mode(file.path(), PaymentMode::Single)
        .await
        .expect("stored with the settled proofs");
    assert_eq!(sent(&direct).await, before + 1, "one transaction in all");
    assert_eq!(
        (record_checkpoints(), upload_checkpoints()),
        checkpoints,
        "nothing kept once stored"
    );
}

/// Storers that refuse every proof on every run, as when the nodes can't
/// read the chain, cost at most one more payment per record across runs: the
/// first run pays; the second, offered the first's proof and refused, pays
/// again once; the third pays nothing. For a chunk put and for a file
/// upload, each stored afterwards.
async fn refusals_on_every_run_pay_again_at_most_once(testnet: Arc<MiniTestnet>) {
    let (_proxy, direct, proxied) = setup(&testnet).await;
    let checkpoints = (record_checkpoints(), upload_checkpoints());

    let content = random_chunk();
    let before = sent(&direct).await;
    {
        let _refusing = Refusing::start();
        for run in 1..=3u64 {
            client(&testnet, &proxied)
                .chunk_put(content.clone())
                .await
                .expect_err("every storer refuses");
            assert_eq!(
                sent(&direct).await,
                before + run.min(2),
                "run {run}: at most one payment more than the first"
            );
        }
    }
    client(&testnet, &proxied)
        .chunk_put(content.clone())
        .await
        .expect("stored with the kept proof");
    assert_eq!(sent(&direct).await, before + 2);

    let file = random_file();
    let before = sent(&direct).await;
    {
        let _refusing = Refusing::start();
        for run in 1..=3u64 {
            client(&testnet, &proxied)
                .file_upload_with_mode(file.path(), PaymentMode::Single)
                .await
                .expect_err("every storer refuses");
            assert_eq!(
                sent(&direct).await,
                before + run.min(2),
                "run {run}: at most one payment more than the first"
            );
        }
    }
    client(&testnet, &proxied)
        .file_upload_with_mode(file.path(), PaymentMode::Single)
        .await
        .expect("stored with the kept proofs");
    assert_eq!(sent(&direct).await, before + 2);
    assert_eq!(
        (record_checkpoints(), upload_checkpoints()),
        checkpoints,
        "nothing kept once stored"
    );
}

/// A chunk paid again because every storer refused its kept proof, whose
/// new payment then fails before anything is sent, keeps the mark: its
/// checkpoint stays, and the runs after it, refused again, pay once more
/// in all, never a third time.
async fn a_failed_payment_after_a_refusal_never_pays_a_third_time(testnet: Arc<MiniTestnet>) {
    let (proxy, direct, proxied) = setup(&testnet).await;
    let checkpoints = record_checkpoints();

    let content = random_chunk();
    let before = sent(&direct).await;
    {
        let _refusing = Refusing::start();
        client(&testnet, &proxied)
            .chunk_put(content.clone())
            .await
            .expect_err("every storer refuses");
        assert_eq!(sent(&direct).await, before + 1, "the first payment");

        // Refused again, the kept proof is paid again; that payment fails
        // before anything is sent.
        proxy.refuse_gas_estimates(true);
        let failed = client(&testnet, &proxied).chunk_put(content.clone()).await;
        proxy.refuse_gas_estimates(false);
        failed.expect_err("the new payment fails before it is sent");
        assert_eq!(sent(&direct).await, before + 1, "nothing sent");
        assert_eq!(
            record_checkpoints(),
            checkpoints + 1,
            "the checkpoint holding the mark stays"
        );

        for run in 1..=2 {
            client(&testnet, &proxied)
                .chunk_put(content.clone())
                .await
                .expect_err("every storer refuses");
            assert_eq!(
                sent(&direct).await,
                before + 2,
                "run {run}: paid again once in all"
            );
        }
    }
    client(&testnet, &proxied)
        .chunk_put(content)
        .await
        .expect("stored with the kept proof");
    assert_eq!(sent(&direct).await, before + 2, "two transactions in all");
    assert_eq!(
        record_checkpoints(),
        checkpoints,
        "nothing kept once stored"
    );
}

/// A kept proof every storer refuses while the vault's record of its
/// payment can't be read (every RPC failing, for the nodes and this client
/// alike) is kept, and nothing is paid; once the chain answers and storers
/// take it, the record is stored with it. For a chunk put and for a file
/// upload.
async fn a_refused_proof_whose_payment_cant_be_read_is_kept(testnet: Arc<MiniTestnet>) {
    let (proxy, direct, proxied) = setup(&testnet).await;
    let checkpoints = (record_checkpoints(), upload_checkpoints());

    let content = random_chunk();
    let file = random_file();
    let before = sent(&direct).await;
    {
        let _refusing = Refusing::start();
        client(&testnet, &proxied)
            .chunk_put(content.clone())
            .await
            .expect_err("every storer refuses");
        client(&testnet, &proxied)
            .file_upload_with_mode(file.path(), PaymentMode::Single)
            .await
            .expect_err("every storer refuses");
        let paid = sent(&direct).await;
        assert_eq!(paid, before + 2, "each paid once");
        proxy.go_down();
        let chunk = client(&testnet, &proxied).chunk_put(content.clone()).await;
        let upload = client(&testnet, &proxied)
            .file_upload_with_mode(file.path(), PaymentMode::Single)
            .await;
        proxy.restore();
        chunk.expect_err("refused, and its payment can't be read");
        upload.expect_err("refused, and its payment can't be read");
        assert_eq!(sent(&direct).await, paid, "nothing paid again");
    }
    client(&testnet, &proxied)
        .chunk_put(content)
        .await
        .expect("stored with the kept proof");
    client(&testnet, &proxied)
        .file_upload_with_mode(file.path(), PaymentMode::Single)
        .await
        .expect("stored with the kept proofs");
    assert_eq!(sent(&direct).await, before + 2, "no payment but the first");
    assert_eq!(
        (record_checkpoints(), upload_checkpoints()),
        checkpoints,
        "nothing kept once stored"
    );
}
