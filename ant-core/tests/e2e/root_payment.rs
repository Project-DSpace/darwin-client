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
//! What such a client hands a payer outside it, a prepared upload or a
//! pointer's quote, is quoted for the per-quote vault: every quote request
//! the nodes received for it declared settlement version 2, never the root
//! vault's 3.
//!
//! A payer outside the client that asks for root waves
//! (`UploadPayer::pays_root_waves`), uploading through a client that names
//! the root vault and holds no wallet for it, as a gateway does, is asked to
//! pay a mixed file's root wave and its per-quote payment, each through its
//! vault; the envelope's record names the transaction that recorded the
//! wave. Interrupted after paying the wave, the upload reconciles it on the
//! next attempt without paying it again. A root request paid at the
//! per-quote vault is stored with single-node proofs.
//!
//! The amount checks are in the four cases of single records (a wave, a wave
//! of one, a record paying the per-quote vault, a mixed wave): every payment
//! there, a wave's leaf or a quote paid through the per-quote vault, is
//! checked to be its record's size-class amount on a curve nodes quote
//! during the upload: `quote_price_at` when the upload starts or when it
//! ends, the earlier x32 curve before ds.20's switch and the new one from
//! it. Which quote paid which amount isn't read here. The file case and the
//! outside payer's case check no amounts. The signing-time rule itself, each
//! leaf its own quote's price on whichever curve that quote was priced, is
//! pinned without the clock by `root_payment`'s unit test
//! `each_leaf_is_its_own_quotes_price_at_its_records_weight_on_either_curve`.

use crate::support::runner::Case;
use crate::support::{MiniTestnet, CLIENT_NODE, ROOT_UNAWARE_NODES};
use ant_core::ant_listings::{
    Envelope, Metadata, PaymentError, ProofError, RootVault, Salt, ShownFields,
    DATA_PAYMENT_MADE_TOPIC,
};
use ant_core::data::client::upload::{MerkleUploadPayment, UploadPayment};
use ant_core::data::{
    compute_address, file_data_map, forget_upload_record, ml_dsa_65, paid_quote_hash,
    proof_data_map, ChunkPaymentPlan, DataMap, Error, ExternalPaymentInfo, ListingChain,
    PaymentMode, Pointer, PointerTarget, PointerTargetKind, PreparedMerkleBatch, UploadEvent,
    UploadPayer, Visibility,
};
use ant_node::payment::pricing::quote_price_at;
use ant_protocol::evm::{Address, Amount, QuoteHash, RewardsAddress, TxHash};
use ant_protocol::payment::pricing::{record_weight, weighted_amount};
use bytes::Bytes;
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
        Case::on_network(
            "root_payment::what_a_root_client_hands_an_outside_payer_is_quoted_for_the_per_quote_vault",
            what_a_root_client_hands_an_outside_payer_is_quoted_for_the_per_quote_vault,
        ),
        Case::on_network(
            "root_payment::a_payer_that_asks_pays_a_mixed_wave_and_the_envelopes_record_names_the_recording_transaction",
            a_payer_that_asks_pays_a_mixed_wave_and_the_envelopes_record_names_the_recording_transaction,
        ),
        Case::on_network(
            "root_payment::a_payers_upload_stopped_after_its_root_wave_reconciles_without_paying_again",
            a_payers_upload_stopped_after_its_root_wave_reconciles_without_paying_again,
        ),
        Case::on_network(
            "root_payment::a_root_request_paid_at_the_per_quote_vault_stores_with_single_node_proofs",
            a_root_request_paid_at_the_per_quote_vault_stores_with_single_node_proofs,
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
    // Quoted at the root vault's settlement version, 3, where the outside
    // payer's case sees version 2 alone.
    testnet.flush_chunk_gets(client.network().node()).await;
    let versions = testnet.quote_versions_received(&address);
    assert!(
        !versions.is_empty() && versions.iter().all(|version| *version == 3),
        "quoted at settlement versions {versions:?}, not 3 alone"
    );
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
    root_file_with(testnet, 0, 0).await
}

/// [`root_file`], with at least `per_quote_records` content records paying
/// the per-quote vault, its content from `n` on.
async fn root_file_with(
    testnet: &MiniTestnet,
    per_quote_records: usize,
    from: u32,
) -> (NamedTempFile, DataMap, usize) {
    for n in from..from + 100_000 {
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
        if roots >= 2 && per_quote >= per_quote_records && roots + per_quote == addresses.len() {
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
    // The devnet's reader, given the root vault its manifest names.
    let reader =
        ListingChain::new_with_root_vault(testnet.evm_network(), Some(vault)).expect("a reader");
    assert_eq!(
        reader.vaults().root,
        Some(RootVault {
            address: vault.into_array(),
            token: testnet.evm_network().payment_token_address().into_array(),
        })
    );
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
    // Refused for the reason a reader of the per-quote vault alone has, not
    // an RPC failure or a transaction it can't find: it keeps only its own
    // vault's logs of a receipt, and the per-quote vault has none paying the
    // quote in this transaction.
    assert_eq!(
        per_quote_reader.check_proof(&record).await.err(),
        Some(ProofError::Payment(PaymentError::NotPaid).to_string()),
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

/// Pay `payments` as a payer outside the client does, through the per-quote
/// vault with the funded wallet, returning the transaction of each quote.
async fn pay_outside(
    testnet: &MiniTestnet,
    payments: Vec<(QuoteHash, RewardsAddress, Amount)>,
) -> HashMap<QuoteHash, TxHash> {
    let (transactions, _) = testnet
        .wallet()
        .pay_for_quotes(payments)
        .await
        .expect("pay outside the client");
    transactions.into_iter().collect()
}

/// What a client paying the root vault hands a payer outside it is quoted
/// for the per-quote vault, at settlement version 2: a prepared upload's
/// records, its envelope among them (`data_prepare_upload`), and a pointer's
/// state (`prepare_pointer_payment`). Every quote request the nodes received
/// for them declared version 2, none the root vault's 3, so none was asked
/// for a root payment the payer can't make, and a close group holding a node
/// without the root vault is quoted once. So is a record quoted without its
/// bytes (`prepare_chunk_payment_plan`), which is not paid here. Paid per
/// quote outside the client, the upload is finished with `finalize_upload`
/// and the pointer stored with `pointer_put_paid`: no wave is paid, and each
/// record and the pointer pay one quote through the per-quote vault.
async fn what_a_root_client_hands_an_outside_payer_is_quoted_for_the_per_quote_vault(
    testnet: Arc<MiniTestnet>,
) {
    let client = testnet.root_client();
    let waves = root_waves(&testnet).await;
    let per_quote = per_quote_payments(&testnet).await;

    let content: Vec<u8> = (0..20_000).map(|_| rand::random::<u8>()).collect();
    let prepared = client
        .data_prepare_upload(Bytes::from(content))
        .await
        .expect("prepare the upload");
    let envelope = prepared.envelope.as_ref().expect("an envelope").address();
    let ExternalPaymentInfo::WaveBatch {
        prepared_chunks,
        payment_intent,
    } = &prepared.payment_info
    else {
        panic!("expected a wave batch");
    };
    let records = prepared_chunks
        .iter()
        .map(|chunk| chunk.address)
        .collect::<Vec<_>>();
    assert!(records.contains(&envelope), "the envelope is prepared too");
    let upload_payments = payment_intent.payments.clone();

    let (public_key, secret_key) = ml_dsa_65().generate_keypair().expect("an owner key");
    let pointer = Pointer::create(
        &secret_key,
        &public_key,
        PointerTarget::new(PointerTargetKind::Chunk, [0x36; 32]),
    )
    .expect("sign the pointer");
    let plan = client
        .prepare_pointer_payment(&pointer)
        .await
        .expect("quote the pointer's state");
    assert!(
        plan.vault.is_v2(),
        "the pointer's plan pays the per-quote vault"
    );
    // A record quoted without its bytes, for a payer to pay
    // (`prepare_chunk_payment_plan`): only quoted here, never paid.
    let unpaid: [u8; 32] = rand::random();
    let chunk_plan = client
        .prepare_chunk_payment_plan(unpaid, 4_096)
        .await
        .expect("quote the record")
        .expect("a record not stored");
    assert!(
        chunk_plan.vault.is_v2(),
        "a chunk's plan pays the per-quote vault"
    );

    testnet.flush_chunk_gets(client.network().node()).await;
    for address in records.iter().chain([&pointer.state_id(), &unpaid]) {
        let versions = testnet.quote_versions_received(address);
        assert!(!versions.is_empty(), "{} was quoted", hex::encode(address));
        assert!(
            versions.iter().all(|version| *version == 2),
            "{} quoted at settlement versions {versions:?}, not 2 alone",
            hex::encode(address)
        );
    }

    let transactions = pay_outside(&testnet, upload_payments).await;
    let result = client
        .finalize_upload(prepared, &transactions)
        .await
        .expect("finalize the upload");
    assert_eq!(result.total_chunks, records.len());
    assert_eq!(result.chunks_stored, records.len());

    let pointer_payments = plan
        .payment
        .quotes
        .iter()
        .filter(|quote| !quote.amount.is_zero())
        .map(|quote| (quote.quote_hash, quote.rewards_address, quote.amount))
        .collect();
    let pointer_transactions = pay_outside(&testnet, pointer_payments).await;
    let proof = plan
        .proof(&pointer_transactions)
        .expect("the pointer's proof");
    client
        .pointer_put_paid(&pointer, proof)
        .await
        .expect("store the pointer");

    assert_eq!(root_waves(&testnet).await, waves, "no wave");
    assert_eq!(
        per_quote_payments(&testnet).await,
        per_quote + records.len() + 1,
        "one quote for each record and the pointer through the per-quote vault"
    );
}

/// A payer outside the client that asks for root waves, as a gateway does:
/// it pays each payment at the vault its plans name, from the funded
/// wallet, a root wave's leaves in ascending quote-hash order, and leaves
/// the wave to the engine to find. Asked again for a payment it made, it
/// returns that payment and sends nothing, as a payer must after a restart.
struct RootPayer<'a> {
    testnet: &'a MiniTestnet,
    /// Who the payer pays for ([`UploadPayer::checkpoint_scope`]).
    account: &'static str,
    /// Send every payment, a root wave's too, to the per-quote vault.
    to_per_quote: bool,
    /// Fail once after paying a root wave, as a payer stopped then.
    stop_after_root: AtomicBool,
    /// Payments asked for, of the root vault's plans and of the other's.
    asked_root: AtomicUsize,
    asked_per_quote: AtomicUsize,
    /// Transactions sent for root plans.
    sent_root: AtomicUsize,
    /// Each payment made, by its quote hashes in order: its transactions
    /// and total.
    made: Mutex<HashMap<Vec<QuoteHash>, MadePayment>>,
}

/// A payment [`RootPayer`] made: its transaction for each quote hash, and
/// its total.
type MadePayment = (HashMap<QuoteHash, TxHash>, Amount);

impl<'a> RootPayer<'a> {
    fn new(testnet: &'a MiniTestnet, account: &'static str) -> Self {
        Self {
            testnet,
            account,
            to_per_quote: false,
            stop_after_root: AtomicBool::new(false),
            asked_root: AtomicUsize::new(0),
            asked_per_quote: AtomicUsize::new(0),
            sent_root: AtomicUsize::new(0),
            made: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl UploadPayer for RootPayer<'_> {
    async fn pay_quotes(
        &self,
        plans: &[ChunkPaymentPlan],
    ) -> ant_core::data::Result<UploadPayment> {
        let root = plans.iter().any(|plan| !plan.vault.is_v2());
        assert!(
            plans.iter().all(|plan| plan.vault.is_v2() != root),
            "one payment pays one vault"
        );
        if root {
            self.asked_root.fetch_add(1, Ordering::SeqCst);
        } else {
            self.asked_per_quote.fetch_add(1, Ordering::SeqCst);
        }
        let mut payments = plans
            .iter()
            .flat_map(|plan| plan.payment.quotes.iter())
            .filter(|quote| !quote.amount.is_zero())
            .map(|quote| (quote.quote_hash, quote.rewards_address, quote.amount))
            .collect::<Vec<_>>();
        payments.sort_by_key(|payment| payment.0);
        let hashes = payments.iter().map(|payment| payment.0).collect::<Vec<_>>();
        let amount = plans
            .iter()
            .fold(Amount::ZERO, |sum, plan| sum + plan.payment.total_amount());
        let made = self.made.lock().unwrap().get(&hashes).cloned();
        if let Some((transactions, amount)) = made {
            return Ok(UploadPayment {
                transactions,
                amount,
                gas: 0,
                root: None,
            });
        }
        let wallet = if root && !self.to_per_quote {
            self.testnet.root_wallet()
        } else {
            self.testnet.wallet().clone()
        };
        let (transactions, gas) = wallet
            .pay_for_quotes(payments)
            .await
            .map_err(|e| Error::Payment(e.0.to_string()))?;
        let transactions = transactions.into_iter().collect::<HashMap<_, _>>();
        if root {
            self.sent_root.fetch_add(1, Ordering::SeqCst);
        }
        self.made
            .lock()
            .unwrap()
            .insert(hashes, (transactions.clone(), amount));
        if root && self.stop_after_root.swap(false, Ordering::SeqCst) {
            return Err(Error::Payment("stopped after paying the root wave".into()));
        }
        Ok(UploadPayment {
            transactions,
            amount,
            gas: gas.gas_cost_wei,
            root: None,
        })
    }

    async fn pay_merkle(
        &self,
        _batch: &PreparedMerkleBatch,
    ) -> ant_core::data::Result<MerkleUploadPayment> {
        Err(Error::Payment("not used here".into()))
    }

    fn checkpoint_scope(&self) -> Vec<u8> {
        self.account.as_bytes().to_vec()
    }

    fn pays_root_waves(&self) -> bool {
        true
    }

    /// The funded wallet approves each vault without limit.
    fn exact_approvals(&self) -> bool {
        false
    }
}

/// A client as a gateway runs one: it names the devnet's root vault
/// ([`ant_core::data::Client::with_root_vault`]) and holds no wallet for
/// it, so it pays the root vault only through a payer outside it.
fn gateway_client(testnet: &MiniTestnet) -> ant_core::data::Client {
    let client = testnet.client().with_root_vault(testnet.root_vault());
    assert!(client.root_wallet().is_none());
    client
}

/// Upload `file` through `payer`, stopping once its envelope's salt is
/// saved (the upload says so with `UploadEvent::Encrypted`, before any
/// quote is asked), and replace the salt with one whose envelope for `map`
/// pays the root vault ([`root_salt`]), so the next upload of the file
/// through the same payer resumes with it. Returns the envelope's address.
async fn stop_with_root_salt(
    testnet: &MiniTestnet,
    client: &ant_core::data::Client,
    payer: &RootPayer<'_>,
    file: &NamedTempFile,
    map: &DataMap,
) -> [u8; 32] {
    let salts = upload_salts();
    {
        let (events, mut received) = tokio::sync::mpsc::channel(64);
        let stopped = client.file_upload_with_payer(
            file.path(),
            Visibility::default(),
            PaymentMode::Single,
            payer,
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
    let (salt, address) = root_salt(testnet, map);
    std::fs::write(&saved[0], salt).expect("replace the salt");
    address
}

/// The file's upload through `payer`, with the default envelope.
async fn upload_through(
    client: &ant_core::data::Client,
    payer: &RootPayer<'_>,
    file: &NamedTempFile,
) -> ant_core::data::Result<ant_core::data::FileUploadResult> {
    client
        .file_upload_with_payer(
            file.path(),
            Visibility::default(),
            PaymentMode::Single,
            payer,
            None,
        )
        .await
}

/// That `result`, the upload of `file` (`map`, its envelope at `address`),
/// stored every record, and its envelope's record checks out through
/// `reader` with no problem at transaction `tx`; the file reads back from
/// the record. Returns the record's transaction.
async fn check_upload(
    testnet: &MiniTestnet,
    reader: &ListingChain,
    file: &NamedTempFile,
    map: &DataMap,
    address: [u8; 32],
    result: &ant_core::data::FileUploadResult,
) -> [u8; 32] {
    assert!(result.data_map == *map);
    assert_eq!(
        result.total_chunks,
        map.infos().len() + 1,
        "and its envelope"
    );
    assert_eq!(result.chunks_stored, result.total_chunks);
    let envelope = result.envelope.clone().expect("an envelope");
    forget_upload_record(&envelope.address()).expect("forget the kept record");
    assert_eq!(envelope.address(), address, "the envelope of the root salt");
    assert_eq!(envelope.proof_problem, None, "the record has no problem");
    assert!(envelope.proof_checked);
    let record = envelope.proof.clone().expect("a record");
    let proven = reader
        .check_proof(&record)
        .await
        .expect("the record checks out");
    assert_eq!(proven.payment.tx_hash, record.tx_hash);
    let revealed = proof_data_map(&record).expect("the revealed data map");
    assert!(revealed == result.data_map);
    let output = TempDir::new().expect("a temp folder");
    let path = output.path().join("paid.bin");
    testnet
        .client()
        .file_download(&revealed, &path)
        .await
        .expect("download");
    assert_eq!(
        std::fs::read(&path).expect("read the download"),
        std::fs::read(file.path()).expect("read the file")
    );
    record.tx_hash
}

/// A payer outside the client that asks for root waves, through a client
/// naming the root vault and holding no wallet for it, uploads a file whose
/// envelope and two or more content records can pay the root vault and at
/// least one content record can't (a node without the root vault is among
/// its closest, [`ROOT_UNAWARE_NODES`]): it is asked for two payments, the
/// root wave first, and the vaults record one wave of the envelope and the
/// content records that can pay it, and a per-quote payment of each other
/// record. The envelope's record names the transaction that recorded the
/// wave and checks out at the root vault.
async fn a_payer_that_asks_pays_a_mixed_wave_and_the_envelopes_record_names_the_recording_transaction(
    testnet: Arc<MiniTestnet>,
) {
    let client = gateway_client(&testnet);
    let vault = testnet.root_vault();
    let reader =
        ListingChain::new_with_root_vault(testnet.evm_network(), Some(vault)).expect("a reader");
    let payer = RootPayer::new(&testnet, "root payer: mixed wave");
    let (file, map, roots) = root_file_with(&testnet, 1, 200_000).await;
    let content_records = map.infos().len();
    assert!(roots < content_records, "a mixed file");
    let address = stop_with_root_salt(&testnet, &client, &payer, &file, &map).await;

    let waves = logs(&testnet, vault, ROOT_PAID).await.len();
    let per_quote = per_quote_payments(&testnet).await;
    let result = upload_through(&client, &payer, &file)
        .await
        .expect("an upload through the payer");
    assert_eq!(payer.asked_root.load(Ordering::SeqCst), 1);
    assert_eq!(payer.asked_per_quote.load(Ordering::SeqCst), 1);
    assert_eq!(payer.sent_root.load(Ordering::SeqCst), 1);

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
        per_quote + content_records - roots,
        "a per-quote payment of each content record that can't pay the root vault"
    );
    let recording = wave.transaction_hash.expect("the wave's transaction").0;
    let named = check_upload(&testnet, &reader, &file, &map, address, &result).await;
    assert_eq!(
        named, recording,
        "the record names the transaction that recorded the wave"
    );
}

/// A payer's upload stopped once its root wave is paid (the payer fails
/// after paying, as one interrupted then) keeps the payment pending; the
/// next upload of the file through the same payer reconciles it, asking the
/// payer for that payment again, which the payer returns without sending
/// anything. One wave is recorded, and the records stored from it.
async fn a_payers_upload_stopped_after_its_root_wave_reconciles_without_paying_again(
    testnet: Arc<MiniTestnet>,
) {
    let client = gateway_client(&testnet);
    let vault = testnet.root_vault();
    let reader =
        ListingChain::new_with_root_vault(testnet.evm_network(), Some(vault)).expect("a reader");
    let payer = RootPayer::new(&testnet, "root payer: stopped");
    payer.stop_after_root.store(true, Ordering::SeqCst);
    let (file, map, _) = root_file_with(&testnet, 0, 400_000).await;
    let address = stop_with_root_salt(&testnet, &client, &payer, &file, &map).await;

    let waves = logs(&testnet, vault, ROOT_PAID).await.len();
    let stopped = upload_through(&client, &payer, &file).await;
    assert!(stopped.is_err(), "the payer stopped after paying the wave");
    assert_eq!(payer.sent_root.load(Ordering::SeqCst), 1);
    assert_eq!(logs(&testnet, vault, ROOT_PAID).await.len(), waves + 1);

    let result = upload_through(&client, &payer, &file)
        .await
        .expect("the upload, reconciled");
    assert_eq!(
        payer.asked_root.load(Ordering::SeqCst),
        2,
        "asked again for the root wave it paid"
    );
    assert_eq!(payer.sent_root.load(Ordering::SeqCst), 1, "sent once");
    let after = logs(&testnet, vault, ROOT_PAID).await;
    assert_eq!(after.len(), waves + 1, "one wave, never paid again");
    let recording = after
        .last()
        .and_then(|wave| wave.transaction_hash)
        .expect("the wave's transaction")
        .0;
    let named = check_upload(&testnet, &reader, &file, &map, address, &result).await;
    assert_eq!(named, recording);
}

/// A root wave's payment sent to the per-quote vault (the same calldata
/// pays either), as a payer sending a root request to its own pinned vault
/// does: the root vault records no wave, the per-quote vault records each
/// quote, and every record, the envelope's among them, is stored with a
/// single-node proof, which the nodes accept for quotes asked at the root
/// vault's settlement version. The envelope's record names the payment's
/// transaction and checks out with a reader of the per-quote vault alone.
async fn a_root_request_paid_at_the_per_quote_vault_stores_with_single_node_proofs(
    testnet: Arc<MiniTestnet>,
) {
    let client = gateway_client(&testnet);
    let per_quote_reader = ListingChain::new(testnet.evm_network()).expect("a reader");
    let mut payer = RootPayer::new(&testnet, "root payer: per-quote vault");
    payer.to_per_quote = true;
    let (file, map, _) = root_file_with(&testnet, 0, 600_000).await;
    let address = stop_with_root_salt(&testnet, &client, &payer, &file, &map).await;

    let waves = root_waves(&testnet).await;
    let per_quote = per_quote_payments(&testnet).await;
    let result = upload_through(&client, &payer, &file)
        .await
        .expect("an upload through the payer");
    assert_eq!(payer.asked_root.load(Ordering::SeqCst), 1, "a root request");
    assert_eq!(root_waves(&testnet).await, waves, "no wave");
    assert_eq!(
        per_quote_payments(&testnet).await,
        per_quote + map.infos().len() + 1,
        "each record and the envelope paid through the per-quote vault"
    );
    check_upload(&testnet, &per_quote_reader, &file, &map, address, &result).await;
}
