//! Upload costs by file size, paid per chunk, on darwin-node.
//!
//! Uploads files of various sizes and reports the token cost, the gas cost,
//! the transactions sent and the chunk counts in a summary table. darwin-node
//! refuses merkle (batch) payments at quote time, so there is no batch column
//! to compare against: the test first checks that a forced-merkle upload is
//! refused with nothing paid, then measures per-chunk uploads.
//!
//! A measurement, not a pin, with uploads of up to 4 GB: CI skips it
//! (`scripts/test-targets.py`). Run it by hand, with `--release`:
//!
//!   cargo test --release -p ant-core --test e2e_upload_costs -- --nocapture

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use ant_core::data::client::merkle::PaymentMode;
use ant_core::data::Client;
use serial_test::serial;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use support::{assert_batch_refused, test_client_config, wallet_spend, MiniTestnet};
use tempfile::TempDir;

/// Simple xorshift64 PRNG for deterministic, incompressible test data.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u8(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 & 0xFF) as u8
    }
}

fn create_test_file(dir: &Path, size: u64, name: &str, seed: u64) -> PathBuf {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).expect("create test file");

    let mut rng = Xorshift64::new(seed);
    let mut remaining = size;
    let write_buf_size: usize = 1024 * 1024;
    let mut buf = vec![0u8; write_buf_size];
    while remaining > 0 {
        let to_write = remaining.min(write_buf_size as u64) as usize;
        for byte in buf.iter_mut().take(to_write) {
            *byte = rng.next_u8();
        }
        file.write_all(&buf[..to_write])
            .expect("write chunk to test file");
        remaining -= to_write as u64;
    }
    file.flush().expect("flush test file");

    path
}

/// Result of a single upload cost measurement.
struct CostResult {
    file_size_mb: u64,
    chunks: usize,
    token_cost_atto: u128,
    gas_cost_wei: u128,
    transactions: u64,
}

/// Measure the token and gas cost, and the transactions sent, of one upload
/// paid per chunk.
async fn measure_upload_cost(
    client: &Client,
    wallet: &ant_protocol::evm::Wallet,
    path: &Path,
    file_size_mb: u64,
) -> CostResult {
    let (sent_before, tokens_before) = wallet_spend(wallet).await;
    let gas_before = wallet
        .balance_of_gas_tokens()
        .await
        .expect("get gas balance before");

    let result = client
        .file_upload_with_mode(path, PaymentMode::Single)
        .await
        .expect("upload should succeed");

    let (sent_after, tokens_after) = wallet_spend(wallet).await;
    let gas_after = wallet
        .balance_of_gas_tokens()
        .await
        .expect("get gas balance after");

    CostResult {
        file_size_mb,
        chunks: result.chunks_stored,
        token_cost_atto: tokens_before.saturating_sub(tokens_after).to::<u128>(),
        gas_cost_wei: gas_before.saturating_sub(gas_after).to::<u128>(),
        transactions: sent_after - sent_before,
    }
}

fn format_atto(atto: u128) -> String {
    if atto == 0 {
        return "0".to_string();
    }
    // 1 token = 10^18 atto
    let whole = atto / 1_000_000_000_000_000_000;
    let frac = atto % 1_000_000_000_000_000_000;
    if whole > 0 {
        format!("{whole}.{frac:018}")
    } else {
        format!("{atto} atto")
    }
}

fn format_wei(wei: u128) -> String {
    if wei == 0 {
        return "0".to_string();
    }
    let gwei = wei / 1_000_000_000;
    if gwei > 0 {
        format!("{gwei} gwei")
    } else {
        format!("{wei} wei")
    }
}

fn print_table(results: &[CostResult]) {
    eprintln!();
    eprintln!("╔══════════╤════════╤══════════════════════════╤══════════════════╤═════╗");
    eprintln!("║ Size     │ Chunks │ Token cost               │ Gas cost         │ Txs ║");
    eprintln!("╠══════════╪════════╪══════════════════════════╪══════════════════╪═════╣");
    for r in results {
        let size = if r.file_size_mb >= 1024 {
            format!("{} GB", r.file_size_mb / 1024)
        } else {
            format!("{} MB", r.file_size_mb)
        };
        eprintln!(
            "║ {:<8} │ {:>6} │ {:<24} │ {:<16} │ {:>3} ║",
            size,
            r.chunks,
            format_atto(r.token_cost_atto),
            format_wei(r.gas_cost_wei),
            r.transactions,
        );
    }
    eprintln!("╚══════════╧════════╧══════════════════════════╧══════════════════╧═════╝");
    eprintln!();
}

/// Upload cost table, paid per chunk.
///
/// Sizes cover a single payment wave through many:
/// 10 MB   -> ~3 chunks
/// 50 MB   -> ~13 chunks
/// 200 MB  -> ~54 chunks  (near the 64-chunk wave)
/// 500 MB  -> ~128 chunks (two waves)
/// 2 GB    -> ~512 chunks
/// 4 GB    -> ~1024 chunks
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_upload_cost_by_size() {
    // More than 16 nodes, so the forced-merkle upload asks them for
    // candidates and they refuse.
    let testnet = MiniTestnet::start(20).await;
    let node = testnet.node(3).expect("Node 3 should exist");
    let client = Client::from_node(Arc::clone(&node), test_client_config())
        .with_wallet(testnet.wallet().clone());
    let wallet = testnet.wallet();

    let work_dir = TempDir::new().expect("create work dir");

    // No batch column: darwin-node refuses batch payments before anything
    // is paid.
    let merkle_path = create_test_file(work_dir.path(), 10 * 1024 * 1024, "merkle.bin", 0xCAFE);
    let before = wallet_spend(wallet).await;
    let error = client
        .file_upload_with_mode(&merkle_path, PaymentMode::Merkle)
        .await
        .expect_err("darwin-node refuses batch payments");
    assert_batch_refused(&error);
    assert_eq!(wallet_spend(wallet).await, before);

    let sizes: Vec<(u64, &str)> = vec![
        (10, "10mb.bin"),
        (50, "50mb.bin"),
        (200, "200mb.bin"),
        (500, "500mb.bin"),
        (2048, "2gb.bin"),
        (4096, "4gb.bin"),
    ];

    let mut results = Vec::new();
    for (size_mb, filename) in &sizes {
        eprintln!("--- {size_mb} MB ---");
        let path = create_test_file(
            work_dir.path(),
            *size_mb * 1024 * 1024,
            filename,
            0xDEAD_BEEF_0000_0000 + *size_mb,
        );
        let result = measure_upload_cost(&client, wallet, &path, *size_mb).await;
        eprintln!(
            "    {} chunks, tokens: {}, gas: {}, {} transaction(s)",
            result.chunks,
            format_atto(result.token_cost_atto),
            format_wei(result.gas_cost_wei),
            result.transactions
        );
        results.push(result);
        // The next file needs the room more than this one does.
        std::fs::remove_file(&path).expect("remove the uploaded file");
    }

    eprintln!("=== UPLOAD COST BY SIZE (per chunk) ===");
    print_table(&results);

    drop(client);
    testnet.teardown().await;
}
