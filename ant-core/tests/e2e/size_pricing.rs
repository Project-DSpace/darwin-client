//! Payments by record size at settlement version 2, against the pinned
//! darwin-node revision: each record pays 3 × the median price × its size
//! class's weight, every storer takes it, and it reads back.
//!
//! The cases are the classes the weight changes at: the smallest class, a
//! middle class, a class's top byte and the byte past it, a full chunk, an
//! envelope, a file whose last chunk is small, and a pointer.

use crate::support::runner::Case;
use crate::support::{wallet_spend, MiniTestnet};
use ant_core::data::{compute_address, Client, EnvelopeOptions, PaymentMode, Visibility};
use ant_protocol::evm::Amount;
use ant_protocol::payment::pricing::{
    record_weight, weighted_amount, RecordWeight, SMALLEST_CLASS_BYTES,
};
use ant_protocol::pointer::{Pointer, PointerTarget, PointerTargetKind, DATA_TYPE_POINTER};
use ant_protocol::pqc::api::ml_dsa_65;
use ant_protocol::{DATA_TYPE_CHUNK, MAX_CHUNK_SIZE};
use bytes::Bytes;
use std::io::Write;
use std::sync::Arc;

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network(
            "size_pricing::each_chunk_pays_its_class_and_is_stored",
            each_chunk_pays_its_class_and_is_stored,
        ),
        Case::on_network(
            "size_pricing::a_file_whose_last_chunk_is_small_is_stored",
            a_file_whose_last_chunk_is_small_is_stored,
        ),
        Case::on_network(
            "size_pricing::an_envelope_is_paid_by_its_class_and_reads_back",
            an_envelope_is_paid_by_its_class_and_reads_back,
        ),
        Case::on_network(
            "size_pricing::a_pointer_pays_a_pointers_weight_and_is_stored",
            a_pointer_pays_a_pointers_weight_and_is_stored,
        ),
    ]
}

/// `len` bytes no other case shares.
fn content(len: usize, seed: u8) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| seed ^ (i % 251) as u8 ^ (i / 251) as u8)
            .collect::<Vec<_>>(),
    )
}

/// Whether `spent` is the weighted amount for `weight` of one of `prices`,
/// the prices the record's storers quoted just before it was paid.
fn is_weighted_amount_of_a_quote(spent: Amount, prices: &[Amount], weight: RecordWeight) -> bool {
    prices
        .iter()
        .any(|price| weighted_amount(*price, weight) == Some(spent))
}

/// Store one chunk of `len` bytes and check what it paid: one transaction,
/// of the weighted amount for its class on one of its quotes, below a full
/// chunk's amount unless it is one.
async fn put_and_check(client: &Client, testnet: &MiniTestnet, len: usize, seed: u8) {
    let bytes = content(len, seed);
    let address = compute_address(&bytes);
    let weight = record_weight(DATA_TYPE_CHUNK, len);
    let prices = client
        .get_store_quotes(&address, len as u64, DATA_TYPE_CHUNK)
        .await
        .expect("quotes")
        .into_iter()
        .map(|quote| quote.3)
        .collect::<Vec<_>>();
    let (sent, tokens) = wallet_spend(testnet.wallet()).await;
    let stored = client.chunk_put(bytes.clone()).await.expect("chunk_put");
    assert_eq!(stored, address);
    let (sent_after, tokens_after) = wallet_spend(testnet.wallet()).await;
    assert_eq!(sent_after, sent + 1, "one transaction for {len} bytes");
    let spent = tokens - tokens_after;
    assert!(
        is_weighted_amount_of_a_quote(spent, &prices, weight),
        "{len} bytes paid {spent}, not the weighted amount of any of {prices:?}"
    );
    if weight == RecordWeight::FULL {
        assert!(prices.iter().any(|price| spent == *price * Amount::from(3)));
    } else {
        let most = prices.iter().max().copied().unwrap() * Amount::from(3);
        assert!(
            spent < most,
            "{len} bytes paid {spent}, a full chunk's {most}"
        );
    }
    let read = client
        .chunk_get(&address)
        .await
        .expect("chunk_get")
        .expect("stored");
    assert_eq!(read.content, bytes);
}

async fn each_chunk_pays_its_class_and_is_stored(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();
    assert_eq!(ant_protocol::CURRENT_SETTLEMENT_VERSION, 2);
    let class_top = 256 * 1024;
    for (len, seed) in [
        // The smallest class.
        (SMALLEST_CLASS_BYTES as usize, 1),
        // A middle class.
        (300_000, 2),
        // A class's top byte, and the byte past it, a class up.
        (class_top, 3),
        (class_top + 1, 4),
        // A full chunk.
        (MAX_CHUNK_SIZE, 5),
    ] {
        put_and_check(&client, &testnet, len, seed).await;
    }
    assert!(
        record_weight(DATA_TYPE_CHUNK, class_top) < record_weight(DATA_TYPE_CHUNK, class_top + 1)
    );
}

/// A file whose last chunk is small is stored and reads back, its chunks
/// each paid by their class, for less than full chunks would cost.
async fn a_file_whose_last_chunk_is_small_is_stored(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();
    let data = content(2 * MAX_CHUNK_SIZE + 20_000, 6);
    let (_, tokens) = wallet_spend(testnet.wallet()).await;
    let result = client.data_upload(data.clone()).await.expect("upload");
    let (_, tokens_after) = wallet_spend(testnet.wallet()).await;
    let read = client
        .data_download(&result.data_map)
        .await
        .expect("download");
    assert_eq!(read, data);
    assert!(tokens_after < tokens, "the upload paid");
}

/// An upload with an envelope stores the envelope, a small record paid by
/// its class, and reads back by it.
async fn an_envelope_is_paid_by_its_class_and_reads_back(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();
    let data = content(20_000, 7).to_vec();
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(&data).expect("write");
    file.flush().expect("flush");
    let result = client
        .file_upload_with_visibility_and_progress(
            file.path(),
            PaymentMode::Single,
            Visibility::Envelope(EnvelopeOptions::unlisted()),
            None,
        )
        .await
        .expect("upload");
    let envelope = result.envelope.expect("an envelope");
    let map = client
        .data_map_fetch(&envelope.address())
        .await
        .expect("the envelope carries the data map");
    let output = tempfile::TempDir::new().unwrap();
    let path = output.path().join("envelope.bin");
    client.file_download(&map, &path).await.expect("download");
    assert_eq!(std::fs::read(path).unwrap(), data);
}

/// A pointer pays a pointer's weight, which every pointer shares, and is
/// stored.
async fn a_pointer_pays_a_pointers_weight_and_is_stored(testnet: Arc<MiniTestnet>) {
    let client = testnet.client();
    let weight = record_weight(DATA_TYPE_POINTER, 0);
    assert!(weight < RecordWeight::FULL);
    let (pk, sk) = ml_dsa_65().generate_keypair().expect("keypair");
    let created = Pointer::create(
        &sk,
        &pk,
        PointerTarget::new(PointerTargetKind::Chunk, [8; 32]),
    )
    .expect("sign");
    let (sent, tokens) = wallet_spend(testnet.wallet()).await;
    let address = client.pointer_put(&created).await.expect("pointer_put");
    let (sent_after, tokens_after) = wallet_spend(testnet.wallet()).await;
    assert_eq!(sent_after, sent + 1, "one transaction");
    let spent = tokens - tokens_after;
    assert!(spent > Amount::ZERO);
    let read = client
        .pointer_get(&address)
        .await
        .expect("pointer_get")
        .expect("stored");
    assert_eq!(read.state_id(), created.state_id());
}
