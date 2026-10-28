//! Fixtures shared by the unit tests.

use crate::envelope::Metadata;
use crate::payment::{PaymentLog, PaymentReceipt, RootVault, VaultSet, DATA_PAYMENT_MADE_TOPIC};
use crate::root::{RootPayment, Wave, ROOT_PAID_TOPIC, TRANSFER_TOPIC};
use ant_protocol::evm::{Amount, PaymentQuote, RewardsAddress};
use ant_protocol::XorName;
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::MlDsaOperations;
use self_encryption::{ChunkInfo, DataMap, XorName as SeXorName};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

pub const VAULT: [u8; 20] = [0x69; 20];
pub const REWARDS: [u8; 20] = [0xab; 20];
pub const BLOCK_TIME: u64 = 1_790_000_000;

/// The tests' root vault, and the token it pays in.
pub const ROOT_VAULT: [u8; 20] = [0x6a; 20];
pub const TOKEN: [u8; 20] = [0x70; 20];
/// The account that sends the tests' root waves.
pub const PAYER: [u8; 20] = [0x50; 20];

/// The vaults the tests take payments from: [`VAULT`], and [`ROOT_VAULT`]
/// paying in [`TOKEN`].
pub const VAULTS: VaultSet = VaultSet::with_root(
    VAULT,
    RootVault {
        address: ROOT_VAULT,
        token: TOKEN,
    },
);

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
        data: Vec::new(),
        log_index,
    }
}

/// `address` as a 32-byte word, as an indexed address topic holds it.
pub fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

/// The logs [`ROOT_VAULT`] writes for `wave`, paid by `payer`, from log index
/// `first` on: [`root_wave_logs_at`] the tests' root vault.
pub fn root_wave_logs(wave: &Wave, payer: [u8; 20], first: u64) -> Vec<PaymentLog> {
    let vault = RootVault {
        address: ROOT_VAULT,
        token: TOKEN,
    };
    root_wave_logs_at(&vault, wave, payer, first)
}

/// The logs `vault` writes for `wave`, paid by `payer`, from log index
/// `first` on: each payment's `DataPaymentMade`, then `RootPaid`, then the
/// vault's token's transfer from the payer to each payee of its sum, in the
/// order the payees first appear. A receipt the vault's own code wrote is
/// these logs exactly ([`receipt_vector`]).
pub fn root_wave_logs_at(
    vault: &RootVault,
    wave: &Wave,
    payer: [u8; 20],
    first: u64,
) -> Vec<PaymentLog> {
    let mut logs: Vec<PaymentLog> = wave
        .payments()
        .iter()
        .map(|payment| PaymentLog {
            address: vault.address,
            topics: vec![
                DATA_PAYMENT_MADE_TOPIC,
                address_word(&payment.payee),
                payment.amount.to_be_bytes::<32>(),
                payment.quote_hash,
            ],
            data: Vec::new(),
            log_index: 0,
        })
        .collect();
    let mut data = address_word(&payer).to_vec();
    data.extend_from_slice(&Amount::from(wave.leaf_count()).to_be_bytes::<32>());
    data.extend_from_slice(&wave.total().to_be_bytes::<32>());
    logs.push(PaymentLog {
        address: vault.address,
        topics: vec![ROOT_PAID_TOPIC, wave.key(&vault.address)],
        data,
        log_index: 0,
    });
    logs.extend(wave.sums().into_iter().map(|(payee, sum)| PaymentLog {
        address: vault.token,
        topics: vec![TRANSFER_TOPIC, address_word(&payer), address_word(&payee)],
        data: sum.to_be_bytes::<32>().to_vec(),
        log_index: 0,
    }));
    for (log, log_index) in logs.iter_mut().zip(first..) {
        log.log_index = log_index;
    }
    logs
}

/// A JSON file.
pub fn read_json(path: PathBuf) -> Value {
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
}

/// A hash or address in a vector file: a 0x-prefixed hex string of exactly
/// `N` bytes.
pub fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"));
    data(value)
        .try_into()
        .unwrap_or_else(|_| panic!("not {N} bytes: {text}"))
}

/// Bytes of any length in a vector file: a 0x-prefixed hex string.
pub fn data(value: &Value) -> Vec<u8> {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"));
    let digits = text.strip_prefix("0x").expect("0x-prefixed");
    crate::proof::decode_hex(digits).expect("hex")
}

/// A list of hashes or addresses.
pub fn list<const N: usize>(value: &Value) -> Vec<[u8; N]> {
    value
        .as_array()
        .expect("a list")
        .iter()
        .map(bytes)
        .collect()
}

/// An integer: a 0x-prefixed hex string, never a JSON number.
pub fn number(value: &Value) -> Amount {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"));
    Amount::from_str_radix(text.strip_prefix("0x").expect("0x-prefixed"), 16).expect("hex")
}

/// An integer as a `u64`, or `u64::MAX` if it doesn't fit.
pub fn small(value: &Value) -> u64 {
    u64::try_from(number(value)).unwrap_or(u64::MAX)
}

/// A vector file's wave: its payments, in order.
pub fn payments(wave: &Value) -> Vec<RootPayment> {
    let quote_hashes = list::<32>(&wave["quoteHashes"]);
    let payees = list::<20>(&wave["payees"]);
    let amounts: Vec<Amount> = wave["amounts"]
        .as_array()
        .expect("a list")
        .iter()
        .map(number)
        .collect();
    assert_eq!(quote_hashes.len(), payees.len());
    assert_eq!(quote_hashes.len(), amounts.len());
    quote_hashes
        .into_iter()
        .zip(payees)
        .zip(amounts)
        .map(|((quote_hash, payee), amount)| RootPayment {
            quote_hash,
            payee,
            amount,
        })
        .collect()
}

/// A wave the root vault's own code recorded on a local chain, and the logs
/// it wrote: `src/root/vectors/receipt.json`.
pub struct ReceiptVector {
    /// The vault, and the token it paid in.
    pub vault: RootVault,
    /// The account that sent the wave.
    pub payer: [u8; 20],
    /// The wave, as sent.
    pub wave: Wave,
    /// The wave's root.
    pub root: [u8; 32],
    /// The key the vault gives the wave.
    pub key: [u8; 32],
    /// What the wave pays in all.
    pub total: Amount,
    /// Each payment's path, which the vault accepts.
    pub paths: Vec<Vec<[u8; 32]>>,
    /// The transaction's logs, in order, as its receipt gives them.
    pub logs: Vec<PaymentLog>,
}

/// The receipt in `src/root/vectors/receipt.json`.
pub fn receipt_vector() -> ReceiptVector {
    let file =
        read_json(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/root/vectors/receipt.json"));
    assert_eq!(file["status"], "0x1");
    let payments = payments(&file);
    assert_eq!(payments.len() as u64, small(&file["leafCount"]));
    let logs = file["logs"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|log| PaymentLog {
            address: bytes(&log["address"]),
            topics: list(&log["topics"]),
            data: data(&log["data"]),
            log_index: small(&log["logIndex"]),
        })
        .collect();
    ReceiptVector {
        vault: RootVault {
            address: bytes(&file["vault"]),
            token: bytes(&file["token"]),
        },
        payer: bytes(&file["payer"]),
        wave: Wave::new(payments).unwrap(),
        root: bytes(&file["root"]),
        key: bytes(&file["key"]),
        total: number(&file["total"]),
        paths: file["paths"]
            .as_array()
            .expect("a list")
            .iter()
            .map(list)
            .collect(),
        logs,
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
