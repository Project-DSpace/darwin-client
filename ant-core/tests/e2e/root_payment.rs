//! Root payments against the pinned darwin-node revision: records paid in
//! waves through the root vault, which runs DarwinRootVault's frozen code
//! on the chain, each record's proof (tag 0x03) naming its leaf, its place
//! in the wave and its path, and every storer that knows the root vault
//! taking it.
//!
//! The shared network's [`ROOT_UNAWARE_NODES`] know no root vault, as nodes
//! on a build before root payments: a record whose close group holds one is
//! quoted, paid and stored through the per-quote vault instead. Each case
//! picks its records' content by where their addresses fall, so which vault
//! a record can pay is known before it is uploaded.
//!
//! Every payment, a wave's leaf or a quote paid through the per-quote vault,
//! is its record's size-class amount priced on the curve of its quote's
//! signing time (`quote_price_at`): the earlier x32 curve before ds.20's
//! switch and the new one from it, as a version-2 record is priced.

use crate::support::runner::Case;
use crate::support::{MiniTestnet, CLIENT_NODE, ROOT_UNAWARE_NODES};
use ant_core::ant_listings::{
    Envelope, Metadata, RootVault, Salt, ShownFields, DATA_PAYMENT_MADE_TOPIC,
};
use ant_core::data::{
    compute_address, file_data_map, forget_upload_record, paid_quote_hash, proof_data_map, DataMap,
    ListingChain, PaymentMode, UploadEvent, Visibility,
};
use ant_node::payment::pricing::quote_price_at;
use ant_protocol::evm::{Address, Amount};
use ant_protocol::payment::pricing::{record_weight, weighted_amount};
use bytes::Bytes;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tempfile::{NamedTempFile, TempDir};

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network(
            "root_payment::a_wave_of_records_pays_the_root_vault_once_and_reads_back",
            a_wave_of_records_pays_the_root_vault_once_and_reads_back,
        ),
        Case::on_network(
            "root_payment::a_single_record_pays_a_wave_of_one",
            a_single_record_pays_a_wave_of_one,
        ),
        Case::on_network(
            "root_payment::a_record_quoted_by_a_node_without_the_root_vault_pays_the_per_quote_vault",
            a_record_quoted_by_a_node_without_the_root_vault_pays_the_per_quote_vault,
        ),
        Case::on_network(
            "root_payment::a_mixed_wave_pays_each_vault_once",
            a_mixed_wave_pays_each_vault_once,
        ),
        Case::on_network(
            "root_payment::a_file_with_the_default_envelope_pays_one_root_wave_and_its_record_names_it",
            a_file_with_the_default_envelope_pays_one_root_wave_and_its_record_names_it,
        ),
    ]
}

/// The size of each record the cases store: a small class, so the waves
/// are quick to store.
const RECORD_LEN: usize = 4096;

/// How many of a record's closest nodes must all know the root vault for
/// the record to count as one that pays it: the close group (7), and two
/// more, so a lookup that sees the group a little differently still finds
/// no node without it.
const ROOT_MARGIN: usize = 9;

/// How near a node without the root vault must be for a record to count as
/// one that can't pay it: among its 3 closest, inside any close group a
/// lookup finds.
const UNAWARE_NEAR: usize = 3;

/// `RootPaid(bytes32 indexed key, address payer, uint256 leafCount, uint256 total)`,
/// the root vault's log of a wave.
const ROOT_PAID: &str = "RootPaid(bytes32,address,uint256,uint256)";

/// `DataPaymentMade(address indexed rewardsAddress, uint256 indexed amount, bytes32 indexed quoteHash)`,
/// both vaults' log of a paid quote.
const DATA_PAYMENT_MADE: &str = "DataPaymentMade(address,uint256,bytes32)";

/// `len` bytes from `seed` and `n`, which no other case shares.
fn content(seed: u8, n: u32) -> Bytes {
    let tag = n.to_le_bytes();
    Bytes::from(
        (0..RECORD_LEN)
            .map(|i| seed ^ tag[i % 4] ^ (i % 251) as u8 ^ (i / 251) as u8 ^ 0x5e)
            .collect::<Vec<_>>(),
    )
}

/// The peer ids of the network's nodes but the client's own, nearest
/// `address` first, as the client's lookups see them.
fn nearest(testnet: &MiniTestnet, address: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut peers = testnet
        .nodes
        .iter()
        .enumerate()
        .filter(|(index, node)| *index != CLIENT_NODE && node.is_up())
        .map(|(_, node)| *node.p2p_node.peer_id().as_bytes())
        .collect::<Vec<_>>();
    peers.sort_by_key(|peer| {
        let mut distance = [0u8; 32];
        for (d, (a, b)) in distance.iter_mut().zip(peer.iter().zip(address)) {
            *d = a ^ b;
        }
        distance
    });
    peers
}

/// Whether every one of `address`'s [`ROOT_MARGIN`] nearest nodes knows the
/// root vault.
fn pays_root(testnet: &MiniTestnet, address: &[u8; 32]) -> bool {
    let unaware = testnet.root_unaware_peers();
    nearest(testnet, address)
        .iter()
        .take(ROOT_MARGIN)
        .all(|peer| !unaware.contains(peer))
}

/// Whether a node without the root vault is among `address`'s
/// [`UNAWARE_NEAR`] nearest.
fn pays_per_quote(testnet: &MiniTestnet, address: &[u8; 32]) -> bool {
    let unaware = testnet.root_unaware_peers();
    nearest(testnet, address)
        .iter()
        .take(UNAWARE_NEAR)
        .any(|peer| unaware.contains(peer))
}

/// `count` records from `seed` that `fits` takes, by trying content in turn.
fn records(
    testnet: &MiniTestnet,
    seed: u8,
    count: usize,
    fits: impl Fn(&MiniTestnet, &[u8; 32]) -> bool,
) -> Vec<Bytes> {
    let found = (0..100_000)
        .map(|n| content(seed, n))
        .filter(|bytes| fits(testnet, &compute_address(bytes)))
        .take(count)
        .collect::<Vec<_>>();
    assert_eq!(found.len(), count, "{count} records from seed {seed}");
    found
}

/// The logs `signature` names at `address`, from the chain's start.
async fn logs(
    testnet: &MiniTestnet,
    address: Address,
    signature: &str,
) -> Vec<alloy::rpc::types::Log> {
    use alloy::providers::{Provider, ProviderBuilder};
    let provider = ProviderBuilder::new().connect_http(testnet.evm_network().rpc_url().clone());
    let filter = alloy::rpc::types::Filter::new()
        .address(address)
        .event_signature(alloy::primitives::keccak256(signature.as_bytes()))
        .from_block(0);
    provider.get_logs(&filter).await.expect("read the logs")
}

/// The leaf counts of the root vault's waves, in the chain's order.
async fn root_waves(testnet: &MiniTestnet) -> Vec<u64> {
    logs(testnet, testnet.root_vault(), ROOT_PAID)
        .await
        .iter()
        .map(|log| {
            let data = &log.data().data;
            assert_eq!(data.len(), 96, "payer, leaf count, total");
            let count = alloy::primitives::U256::from_be_slice(&data[32..64]);
            u64::try_from(count).expect("a leaf count")
        })
        .collect()
}

/// The amounts `vault` has recorded paid, in the chain's order: its
/// `DataPaymentMade` logs of a nonzero amount, one for each paid quote (the
/// root vault logs one for each leaf of a wave, before the wave's
/// `RootPaid`).
async fn paid_amounts(testnet: &MiniTestnet, vault: Address) -> Vec<Amount> {
    logs(testnet, vault, DATA_PAYMENT_MADE)
        .await
        .iter()
        .filter_map(|log| log.topics().get(2))
        .map(|amount| Amount::from_be_bytes(amount.0))
        .filter(|amount| !amount.is_zero())
        .collect()
}

/// The per-quote vault's address.
fn per_quote_vault(testnet: &MiniTestnet) -> Address {
    *testnet.evm_network().payment_vault_address()
}

/// How many quotes the per-quote vault has recorded a payment of: its
/// `DataPaymentMade` logs of a nonzero amount.
async fn per_quote_payments(testnet: &MiniTestnet) -> usize {
    paid_amounts(testnet, per_quote_vault(testnet)).await.len()
}

/// What a record of [`RECORD_LEN`] bytes pays when its quotes are signed at
/// `at`: its size class's share of three times the price the shared
/// network's nodes (no commitment, count 0) quote at `at`, on the earlier
/// x32 curve before ds.20's switch and the new one from it.
fn record_amount_at(at: SystemTime) -> Amount {
    let weight = record_weight(ant_protocol::DATA_TYPE_CHUNK, RECORD_LEN);
    weighted_amount(quote_price_at(0, at), weight).expect("a record's amount")
}

/// Each of `paid`, the amounts paid for records whose quotes were all
/// signed between `before` and `after`, is a record's amount on the curve
/// nodes quote during the upload: `before`'s curve or `after`'s, the same
/// curve unless the switch fell between them. Which quote paid which amount
/// isn't read here; the unit tests of `root_payment` pin that each leaf is
/// its own quote's price.
fn assert_priced_at_signing(paid: &[Amount], before: SystemTime, after: SystemTime) {
    let amounts = [record_amount_at(before), record_amount_at(after)];
    for amount in paid {
        assert!(
            amounts.contains(amount),
            "paid {amount}, not a record's amount on the curve nodes quote during the upload \
             ({amounts:?})"
        );
    }
}

/// Each of `stored` reads back as its content, from `client`.
async fn reads_back(client: &ant_core::data::Client, stored: &[Bytes]) {
    for bytes in stored {
        let address = compute_address(bytes);
        let read = client
            .chunk_get(&address)
            .await
            .expect("chunk_get")
            .unwrap_or_else(|| panic!("{} is stored", hex::encode(address)));
        assert_eq!(read.content, *bytes);
    }
}

/// Six records whose close groups all know the root vault are paid as one
/// wave: one `RootPaid` of six leaves, nothing through the per-quote vault,
/// and every record stored with its root proof, which reads back.
async fn a_wave_of_records_pays_the_root_vault_once_and_reads_back(testnet: Arc<MiniTestnet>) {
    assert_eq!(ROOT_UNAWARE_NODES.len(), 2);
    let client = testnet.root_client();
    let chunks = records(&testnet, 0x31, 6, pays_root);
    let waves = root_waves(&testnet).await;
    let per_quote = per_quote_payments(&testnet).await;
    let leaves = paid_amounts(&testnet, testnet.root_vault()).await.len();
    let quoted_from = SystemTime::now();
    let (addresses, _, _) = client
        .batch_upload_chunks(chunks.clone())
        .await
        .expect("a root wave upload");
    let paid_by = SystemTime::now();
    assert_eq!(addresses.len(), chunks.len());
    let after = root_waves(&testnet).await;
    assert_eq!(after.len(), waves.len() + 1, "one wave: {after:?}");
    assert_eq!(after.last(), Some(&6), "of six leaves");
    assert_eq!(
        per_quote_payments(&testnet).await,
        per_quote,
        "nothing through the per-quote vault"
    );
    let paid = paid_amounts(&testnet, testnet.root_vault())
        .await
        .split_off(leaves);
    assert_eq!(paid.len(), 6, "a payment for each leaf: {paid:?}");
    assert_priced_at_signing(&paid, quoted_from, paid_by);
    reads_back(&testnet.client(), &chunks).await;
}

/// A record stored on its own through a client paying the root vault is
/// paid as a wave of one leaf, and stored.
async fn a_single_record_pays_a_wave_of_one(testnet: Arc<MiniTestnet>) {
    let client = testnet.root_client();
    let chunk = records(&testnet, 0x32, 1, pays_root).remove(0);
    let waves = root_waves(&testnet).await;
    let per_quote = per_quote_payments(&testnet).await;
    let leaves = paid_amounts(&testnet, testnet.root_vault()).await.len();
    let quoted_from = SystemTime::now();
    let address = client.chunk_put(chunk.clone()).await.expect("chunk_put");
    let paid_by = SystemTime::now();
    assert_eq!(address, compute_address(&chunk));
    let after = root_waves(&testnet).await;
    assert_eq!(after.len(), waves.len() + 1, "one wave: {after:?}");
    assert_eq!(after.last(), Some(&1), "of one leaf");
    assert_eq!(per_quote_payments(&testnet).await, per_quote);
    let paid = paid_amounts(&testnet, testnet.root_vault())
        .await
        .split_off(leaves);
    assert_eq!(paid.len(), 1, "a payment for the leaf: {paid:?}");
    assert_priced_at_signing(&paid, quoted_from, paid_by);
    reads_back(&testnet.client(), &[chunk]).await;
}

/// A record whose close group holds a node without the root vault is
/// quoted for the per-quote vault and paid there, by a client paying the
/// root vault, and stored: no wave is paid for it.
async fn a_record_quoted_by_a_node_without_the_root_vault_pays_the_per_quote_vault(
    testnet: Arc<MiniTestnet>,
) {
    let client = testnet.root_client();
    let chunk = records(&testnet, 0x33, 1, pays_per_quote).remove(0);
    let waves = root_waves(&testnet).await;
    let per_quote = per_quote_payments(&testnet).await;
    let quoted_from = SystemTime::now();
    client.chunk_put(chunk.clone()).await.expect("chunk_put");
    let paid_by = SystemTime::now();
    assert_eq!(root_waves(&testnet).await, waves, "no wave");
    assert_eq!(
        per_quote_payments(&testnet).await,
        per_quote + 1,
        "one quote paid through the per-quote vault"
    );
    let paid = paid_amounts(&testnet, per_quote_vault(&testnet))
        .await
        .split_off(per_quote);
    assert_priced_at_signing(&paid, quoted_from, paid_by);
    reads_back(&testnet.client(), &[chunk]).await;
}

/// A wave of five records that can pay the root vault and one that can't
/// pays each vault once: a wave of five leaves, and one quote through the
/// per-quote vault. Every record is stored.
async fn a_mixed_wave_pays_each_vault_once(testnet: Arc<MiniTestnet>) {
    let client = testnet.root_client();
    let mut chunks = records(&testnet, 0x34, 5, pays_root);
    chunks.extend(records(&testnet, 0x35, 1, pays_per_quote));
    let waves = root_waves(&testnet).await;
    let per_quote = per_quote_payments(&testnet).await;
    let leaves = paid_amounts(&testnet, testnet.root_vault()).await.len();
    let quoted_from = SystemTime::now();
    let (addresses, _, _) = client
        .batch_upload_chunks(chunks.clone())
        .await
        .expect("a mixed upload");
    let paid_by = SystemTime::now();
    assert_eq!(addresses.len(), chunks.len());
    let after = root_waves(&testnet).await;
    assert_eq!(after.len(), waves.len() + 1, "one wave: {after:?}");
    assert_eq!(after.last(), Some(&5), "of five leaves");
    assert_eq!(
        per_quote_payments(&testnet).await,
        per_quote + 1,
        "one quote through the per-quote vault"
    );
    let mut paid = paid_amounts(&testnet, testnet.root_vault())
        .await
        .split_off(leaves);
    assert_eq!(paid.len(), 5, "a payment for each leaf: {paid:?}");
    paid.extend(
        paid_amounts(&testnet, per_quote_vault(&testnet))
            .await
            .split_off(per_quote),
    );
    assert_priced_at_signing(&paid, quoted_from, paid_by);
    reads_back(&testnet.client(), &chunks).await;
}

/// The size of each file the envelope case uploads: three content records,
/// each in the smallest size class.
const FILE_LEN: usize = 20_000;

/// A file of [`FILE_LEN`] bytes from `n`, which no other case shares.
fn file_content(n: u32) -> Vec<u8> {
    let tag = n.to_le_bytes();
    (0..FILE_LEN)
        .map(|i| tag[i % 4] ^ (i % 253) as u8 ^ (i / 253) as u8 ^ 0xa7)
        .collect()
}

/// The first file whose content records, as the upload encrypts them
/// ([`file_data_map`]), each pay a known vault: at least two the root vault
/// ([`pays_root`]) and the rest the per-quote vault ([`pays_per_quote`]).
/// With the envelope, at least 3 records then pay the root vault, which a
/// payment keeps apart from the rest. Returns the file, its data map and
/// how many of its content records pay the root vault.
///
/// Not every content record need pay the root vault: how much of the
/// address space a node is near depends on where the network's random node
/// ids fall, and in some networks three records all doing so took thousands
/// of files.
async fn root_file(testnet: &MiniTestnet) -> (NamedTempFile, DataMap, usize) {
    for n in 0..100_000 {
        let mut file = NamedTempFile::new().expect("a temp file");
        file.write_all(&file_content(n)).expect("write the file");
        file.flush().expect("flush the file");
        let map = file_data_map(file.path()).await.expect("encrypt the file");
        let addresses = map
            .infos()
            .iter()
            .map(|info| info.dst_hash.0)
            .collect::<Vec<_>>();
        let roots = addresses
            .iter()
            .filter(|address| pays_root(testnet, address))
            .count();
        let per_quote = addresses
            .iter()
            .filter(|address| pays_per_quote(testnet, address))
            .count();
        if roots >= 2 && roots + per_quote == addresses.len() {
            return (file, map, roots);
        }
    }
    panic!("no file whose content records each pay a known vault, two of them the root vault");
}

/// The salt files in the client's data directory: an upload keeps its
/// private envelope's salt next to its checkpoint until it finishes, so an
/// interrupted upload resumes with the same envelope.
fn upload_salts() -> BTreeSet<PathBuf> {
    let directory = ant_core::config::data_dir()
        .expect("the data directory")
        .join("payments/upload");
    match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|e| e == "salt"))
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

/// A salt whose private envelope for `map`, as an upload with the default
/// envelope builds it, pays the root vault ([`pays_root`]), and that
/// envelope's address.
fn root_salt(testnet: &MiniTestnet, map: &DataMap) -> (Salt, [u8; 32]) {
    (0u32..100_000)
        .find_map(|n| {
            let mut salt = [0x5a; 32];
            salt[..4].copy_from_slice(&n.to_le_bytes());
            let envelope =
                Envelope::withheld(map, &salt, Metadata::default(), ShownFields::ALL, false)
                    .expect("the private envelope");
            pays_root(testnet, &envelope.address()).then(|| (salt, envelope.address()))
        })
        .expect("a salt whose envelope pays the root vault")
}

/// A file uploaded with the default envelope (private, all five payment
/// fields shown) by a client paying the root vault, the envelope and at
/// least two content records paying it: one wave holds them, and the
/// envelope's record, built from its root proof, is checked against the
/// chain with no problem, shows all five payment fields, and names the
/// transaction that recorded the wave. A reader of the per-quote vault alone
/// can't check it.
///
/// A private envelope's address comes from its salt, which the upload picks
/// at random, so which vault it pays would be known only once it is quoted.
/// So the upload is first stopped once it has saved its salt (it says so
/// with `UploadEvent::Encrypted`, before any quote is asked), the salt is
/// replaced with one whose envelope pays the root vault, and the upload run
/// again resumes with it, as an interrupted upload does.
async fn a_file_with_the_default_envelope_pays_one_root_wave_and_its_record_names_it(
    testnet: Arc<MiniTestnet>,
) {
    let client = testnet.root_client();
    let vault = testnet.root_vault();
    let per_quote_reader = ListingChain::new(testnet.evm_network()).expect("a reader");
    let reader = ListingChain::new(testnet.evm_network())
        .expect("a reader")
        .with_root_vault(RootVault {
            address: vault.into_array(),
            token: testnet.evm_network().payment_token_address().into_array(),
        });
    let (file, map, roots) = root_file(&testnet).await;
    let content_records = map.infos().len();

    // The upload, stopped once its envelope's salt is saved.
    let salts = upload_salts();
    {
        let (events, mut received) = tokio::sync::mpsc::channel(64);
        let stopped = client.file_upload_with_visibility_and_progress(
            file.path(),
            PaymentMode::default(),
            Visibility::default(),
            Some(events),
        );
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                biased;
                event = received.recv() => match event {
                    Some(UploadEvent::Encrypted { .. }) => break,
                    Some(_) => {}
                    None => panic!("the upload sent no Encrypted event"),
                },
                outcome = &mut stopped => {
                    panic!("the upload ended before it could be stopped: {:?}", outcome.err())
                }
            }
        }
    }
    let saved = upload_salts()
        .difference(&salts)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        saved.len(),
        1,
        "the stopped upload saved its salt: {saved:?}"
    );
    let (salt, address) = root_salt(&testnet, &map);
    std::fs::write(&saved[0], salt).expect("replace the salt");

    let waves = logs(&testnet, vault, ROOT_PAID).await.len();
    let per_quote = per_quote_payments(&testnet).await;
    let result = client
        .file_upload_with_visibility_and_progress(
            file.path(),
            PaymentMode::default(),
            Visibility::default(),
            None,
        )
        .await
        .expect("a file upload with the default envelope");
    assert!(result.data_map == map);
    assert_eq!(result.total_chunks, content_records + 1, "and its envelope");
    assert_eq!(result.chunks_stored, result.total_chunks);
    let envelope = result.envelope.clone().expect("an envelope");
    forget_upload_record(&envelope.address()).expect("forget the kept record");
    assert_eq!(
        envelope.address(),
        address,
        "the envelope of the salt it resumed with"
    );
    assert_eq!(envelope.salt, Some(salt));
    let flags = envelope.envelope.flags();
    assert_eq!(
        flags.shown,
        ShownFields::ALL,
        "all five payment fields shown"
    );
    assert!(flags.withheld && !flags.in_index, "private, the default");
    assert_eq!(envelope.proof_problem, None, "the record has no problem");
    assert!(envelope.proof_checked);
    let record = envelope.proof.clone().expect("a record");
    assert_eq!(record.address, envelope.address());

    // One wave: the envelope and the content records that pay the root
    // vault. The others pay the per-quote vault.
    let after = logs(&testnet, vault, ROOT_PAID).await;
    assert_eq!(after.len(), waves + 1, "one wave: {}", after.len() - waves);
    let wave = after.last().expect("the wave's log");
    let leaves = alloy::primitives::U256::from_be_slice(&wave.data().data[32..64]);
    assert_eq!(
        leaves,
        alloy::primitives::U256::from(roots + 1),
        "the envelope and the content records paying the root vault are its leaves"
    );
    assert_eq!(
        per_quote_payments(&testnet).await,
        per_quote + content_records - roots
    );
    let recording = wave.transaction_hash.expect("the wave's transaction").0;
    assert_eq!(
        record.tx_hash, recording,
        "the record names the transaction that recorded the wave"
    );

    // The record checks out with the root vault, every field shown, at the
    // root vault's log of the envelope's paid quote in that transaction.
    let proven = reader
        .check_proof(&record)
        .await
        .expect("the record checks out at the root vault");
    assert_eq!(proven.payment.tx_hash, recording);
    assert_eq!(
        proven.payment.mask(flags.shown).present(),
        ShownFields::ALL,
        "all five payment fields shown"
    );
    let (receipt, _) = reader
        .transaction(&recording)
        .await
        .expect("the chain answers")
        .expect("the transaction is on chain");
    let paid = paid_quote_hash(&record.quote).expect("the paid quote");
    let leaf_log = receipt
        .logs
        .iter()
        .find(|log| {
            log.address == vault.into_array()
                && log.topics.first() == Some(&DATA_PAYMENT_MADE_TOPIC)
                && log.topics.get(3) == Some(&paid)
        })
        .expect("the envelope's paid quote is a leaf of the wave");
    assert_eq!(proven.payment.log_index, leaf_log.log_index);
    assert!(
        per_quote_reader.check_proof(&record).await.is_err(),
        "a reader of the per-quote vault alone can't check a root payment"
    );

    // The record reveals the file, which reads back.
    let revealed = proof_data_map(&record).expect("the revealed data map");
    assert!(revealed == result.data_map);
    let output = TempDir::new().expect("a temp folder");
    let path = output.path().join("root.bin");
    testnet
        .client()
        .file_download(&revealed, &path)
        .await
        .expect("download");
    assert_eq!(
        std::fs::read(&path).expect("read the download"),
        std::fs::read(file.path()).expect("read the file")
    );
}
