//! Fixtures shared by the unit tests.

use crate::envelope::Metadata;
use crate::payment::{PaymentLog, PaymentReceipt, DATA_PAYMENT_MADE_TOPIC};
use ant_protocol::evm::{Amount, PaymentQuote, RewardsAddress};
use ant_protocol::XorName;
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::MlDsaOperations;
use self_encryption::{ChunkInfo, DataMap, XorName as SeXorName};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

pub const VAULT: [u8; 20] = [0x69; 20];
pub const REWARDS: [u8; 20] = [0xab; 20];
pub const BLOCK_TIME: u64 = 1_790_000_000;

/// A data map with one chunk per entry of `sizes`.
pub fn data_map(sizes: &[usize]) -> DataMap {
    let infos = sizes
        .iter()
        .enumerate()
        .map(|(index, &src_size)| ChunkInfo {
            index,
            dst_hash: SeXorName([u8::try_from(index % 100).unwrap() + 1; 32]),
            src_hash: SeXorName([u8::try_from(index % 100).unwrap() + 100; 32]),
            src_size,
        })
        .collect();
    DataMap::new(infos)
}

pub fn metadata(content_type: Option<&str>, name: Option<&str>) -> Metadata {
    Metadata {
        content_type: content_type.map(str::to_string),
        name: name.map(str::to_string),
    }
}

/// A quote for `content`, signed with the tests' ML-DSA-65 key, paying
/// [`REWARDS`]. Every call gives a different quote, with its own price and
/// so its own hash.
pub fn signed_quote(content: XorName) -> PaymentQuote {
    signed_quote_at(content, quoted_at())
}

/// [`signed_quote`], timestamped `timestamp`, as a node whose clock says so
/// would sign it.
pub fn signed_quote_at(content: XorName, timestamp: SystemTime) -> PaymentQuote {
    static KEY: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    quote_signed_with(&KEY, content, REWARDS, timestamp)
}

/// A quote anyone can make for `content`: signed with a key of their own
/// (not the one [`signed_quote`] uses) and paying their own `rewards`
/// address.
pub fn self_issued_quote(content: XorName, rewards: [u8; 20]) -> PaymentQuote {
    static KEY: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    quote_signed_with(&KEY, content, rewards, quoted_at())
}

/// The tests' quote time: a minute before [`BLOCK_TIME`].
fn quoted_at() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(BLOCK_TIME - 60)
}

fn quote_signed_with(
    key: &OnceLock<(Vec<u8>, Vec<u8>)>,
    content: XorName,
    rewards: [u8; 20],
    timestamp: SystemTime,
) -> PaymentQuote {
    static PRICE: AtomicU64 = AtomicU64::new(87);
    let ml_dsa = MlDsa65::new();
    let (public_key, secret_key) = key.get_or_init(|| {
        let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
        (
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        )
    });
    let mut quote = PaymentQuote {
        content: SeXorName(content),
        timestamp,
        price: Amount::from(PRICE.fetch_add(1, Ordering::Relaxed)),
        rewards_address: RewardsAddress::new(rewards),
        pub_key: public_key.clone(),
        signature: Vec::new(),
        committed_key_count: 0,
        commitment_pin: None,
    };
    let secret_key = MlDsaSecretKey::from_bytes(secret_key).unwrap();
    quote.signature = ml_dsa
        .sign(&secret_key, &quote.bytes_for_sig())
        .unwrap()
        .as_bytes()
        .to_vec();
    quote
}

/// `quote` with a fraction of a second added to its timestamp, as a node's
/// clock gives it. Its signature and hash only cover whole seconds, so it
/// still checks out.
pub fn with_nanos(quote: &PaymentQuote) -> PaymentQuote {
    let mut quote = quote.clone();
    quote.timestamp += Duration::from_nanos(123_456_789);
    quote
}

/// The vault's `DataPaymentMade` log paying `quote` to its rewards address.
pub fn payment_log(quote: &PaymentQuote, log_index: u64) -> PaymentLog {
    let mut rewards = [0u8; 32];
    rewards[12..].copy_from_slice(quote.rewards_address.as_slice());
    let mut amount = [0u8; 32];
    amount[31] = 87;
    PaymentLog {
        address: VAULT,
        topics: vec![DATA_PAYMENT_MADE_TOPIC, rewards, amount, quote.hash().0],
        log_index,
    }
}

pub fn receipt(tx_hash: [u8; 32], block_number: u64, logs: Vec<PaymentLog>) -> PaymentReceipt {
    PaymentReceipt {
        tx_hash,
        success: true,
        block_number,
        logs,
    }
}
