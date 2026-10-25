//! File operations using streaming self-encryption.
//!
//! Upload files directly from disk without loading them entirely into memory.
//! Uses `stream_encrypt` to process files in 8KB chunks, encrypting and
//! uploading each piece as it's produced.
//!
//! Encrypted chunks are spilled to a temporary directory during encryption
//! so that peak memory usage is bounded to one wave (~256 MB for 64 × 4 MB
//! chunks) regardless of file size.
//!
//! For in-memory data uploads, see the `data` module.

use super::*;
use crate::data::client::adaptive::observe_op;
use crate::data::client::batch::{
    finalize_batch_payment, ChunkPaymentPlan, PaidChunk, PaymentIntent, PreparedChunk,
    WaveAggregateStats, WaveResult,
};
use crate::data::client::chunk::{ChunkFetchDiagnostics, ChunkPeerGetResult};
use crate::data::client::classify_error;
use crate::data::client::diagnostics::DownloadDiagnosticsSender;
use crate::data::client::envelope::{EnvelopeOptions, UploadEnvelope};
use crate::data::client::merkle::{
    finalize_merkle_batch, merge_merkle_batch_results, merkle_deferred_retry,
    merkle_store_with_retry, merkle_upload_billable_units, merkle_upload_split, should_use_merkle,
    MerkleBatchPaymentResult, PaymentMode, PreparedMerkleBatch, DEFERRED_ROUND_DELAYS_SECS,
};
use crate::data::client::native_payment::{payment_outcome_unknown, PAYMENT_RECHECK_DELAY};
use crate::data::client::occupied::{
    occupied_at_finalize, plans_of, set_aside_occupied, skipped_amount,
};
use crate::data::client::Client;
use crate::data::error::{Error, PartialUploadSpend, Result};
use ant_protocol::evm::{Amount, PaymentQuote, QuoteHash, TxHash, MAX_LEAVES};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::{compute_address, XorName as ChunkAddress, DATA_TYPE_CHUNK};
use bytes::Bytes;
use fs2::FileExt;
use futures::stream::StreamExt;
use self_encryption::{
    stream_decrypt_batch_size, stream_encrypt, streaming_decrypt_with_batch_size, DataMap,
};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use xor_name::XorName;

/// One entry in the per-chunk quote list returned by
/// [`Client::get_store_quotes`]: the responding peer, its addresses, the
/// signed quote it returned, the payment amount it is demanding, and (ADR-0004)
/// the opaque signed-commitment blob the node shipped with the quote.
type QuoteEntry = (
    PeerId,
    Vec<MultiAddr>,
    PaymentQuote,
    Amount,
    Option<Vec<u8>>,
);

type DownloadBatchEntry = (usize, std::result::Result<Bytes, XorName>);

#[derive(Debug, Clone)]
struct RecordedFileChunkPeerSweep {
    index: usize,
    address: ChunkAddress,
    sweep: FileChunkPeerSweepReport,
}

#[derive(Clone)]
struct FileDownloadFetchContext {
    total_chunks: usize,
    peer_count: usize,
    fetched_ref: Arc<std::sync::atomic::AtomicUsize>,
    progress_ref: Option<mpsc::Sender<DownloadEvent>>,
    peer_reports: Option<Arc<Mutex<Vec<RecordedFileChunkPeerSweep>>>>,
    /// Optional runtime-gated download diagnostics sender. `None` when
    /// `--download-diagnostics` was not passed, so the chunk-fetch path
    /// skips all record construction and allocation.
    diagnostics: Option<DownloadDiagnosticsSender>,
}

/// Number of chunks per upload wave (matches batch.rs PAYMENT_WAVE_SIZE).
const UPLOAD_WAVE_SIZE: usize = super::super::batch::PAYMENT_WAVE_SIZE;

/// Hard ceiling on chunk bodies held in memory at once by the merkle whole-file
/// store fan-out (`upload_merkle_from_spill`). Each in-flight store holds one
/// spilled body (≤ `MAX_CHUNK_SIZE` = 4 MiB), so this bounds peak resident store
/// memory at ~256 MiB — the same bound the old fixed 64-chunk waves gave. The
/// adaptive store cap can legitimately exceed this (`AdaptiveConfig::sanitize`
/// permits `adaptive.max.store` above 64), so the fan-out clamps its cap here to
/// keep a high configured max from pinning gigabytes of chunk bodies (PR #137
/// review). Throughput is unaffected at the default cap, which is already 64.
const MERKLE_STORE_MAX_IN_FLIGHT: usize = 64;

/// The merkle whole-file store fan-out concurrency: the adaptive store cap,
/// clamped to [`MERKLE_STORE_MAX_IN_FLIGHT`] (memory bound) and floored at 1.
fn merkle_store_cap(limiter_current: usize) -> usize {
    limiter_current.clamp(1, MERKLE_STORE_MAX_IN_FLIGHT)
}

/// Stream decrypt batches should be larger than fetch fan-out so
/// the rolling fetch scheduler can keep launching new chunk GETs as earlier
/// ones complete, instead of stopping at each self-encryption batch boundary.
const DOWNLOAD_STREAM_BATCH_FETCH_MULTIPLIER: usize = 4;

/// Use at most this fraction of currently usable RAM for one decrypt batch.
const DOWNLOAD_STREAM_BATCH_MEMORY_BUDGET_DIVISOR: u64 = 4;

/// A decrypt batch briefly holds encrypted chunk bytes, decrypted chunk bytes,
/// and Vec/Bytes overhead. Use a conservative multiplier rather than assuming
/// payload bytes alone.
const DOWNLOAD_STREAM_BATCH_BYTES_PER_CHUNK_MULTIPLIER: u64 = 3;

/// Maximum number of distinct chunk addresses to sample when probing for a
/// representative quote in [`Client::estimate_upload_cost`].
///
/// Bounded small so we never spend more than a couple of round-trips on the
/// `AlreadyStored` retry path, which only matters when many leading chunks
/// of a file already live on the network.
const ESTIMATE_SAMPLE_CAP: usize = 5;

/// First normal-path diagnostic fetch attempt.
const FIRST_DIAGNOSTIC_FETCH_ATTEMPT: usize = 1;

/// Pick up to `cap` chunk indices spread evenly across `[0, total)`, always
/// including the first and last chunk.
///
/// Sampling the *first* N chunks biases the probe: a file sharing a leading
/// prefix with a prior upload (compressed archives, similar headers) reports
/// those chunks as `AlreadyStored` even when the tail is new, so a positional
/// sample looks in the worst possible place. Spreading the sample means a
/// single new chunk anywhere in the file yields a real price.
///
/// Returns `[0]` for a single chunk and every index when `total <= cap`, so
/// [`Client::estimate_upload_cost`] can still detect the "whole file sampled"
/// case. Indices are strictly increasing.
fn distributed_sample_indices(total: usize, cap: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    let sample_limit = total.min(cap);
    if sample_limit <= 1 {
        return vec![0];
    }
    let mut indices: Vec<usize> = (0..sample_limit)
        .map(|i| i * (total - 1) / (sample_limit - 1))
        .collect();
    indices.dedup(); // defensive: already strictly increasing for cap >= 2
    indices
}

fn file_chunk_sweep_report_from_peer_results(
    attempt: usize,
    deferred_retry: bool,
    results: &[ChunkPeerGetResult],
) -> (Option<Bytes>, FileChunkPeerSweepReport) {
    let mut content = None;
    let peers = results
        .iter()
        .map(|result| {
            if content.is_none() {
                if let Ok(Some(chunk)) = &result.chunk_result {
                    content = Some(chunk.content.clone());
                }
            }

            FileChunkPeerReportPeer {
                peer_id: result.peer_id,
                peer_addrs: result.peer_addrs.clone(),
                xor_distance: result.xor_distance,
                status: file_chunk_peer_status(&result.chunk_result),
            }
        })
        .collect();

    (
        content,
        FileChunkPeerSweepReport {
            attempt,
            deferred_retry,
            error: None,
            peers,
        },
    )
}

fn file_chunk_sweep_report_from_error(
    attempt: usize,
    deferred_retry: bool,
    error: &Error,
) -> FileChunkPeerSweepReport {
    FileChunkPeerSweepReport {
        attempt,
        deferred_retry,
        error: Some(error.to_string()),
        peers: Vec::new(),
    }
}

fn file_chunk_reports_from_recorded_sweeps(
    mut sweeps: Vec<RecordedFileChunkPeerSweep>,
) -> Vec<FileChunkPeerReport> {
    sweeps.sort_by_key(|record| (record.index, record.sweep.attempt));

    let mut reports: Vec<FileChunkPeerReport> = Vec::new();
    for record in sweeps {
        if let Some(report) = reports
            .last_mut()
            .filter(|report| report.index == record.index)
        {
            report.sweeps.push(record.sweep);
            continue;
        }

        reports.push(FileChunkPeerReport {
            index: record.index,
            address: record.address,
            sweeps: vec![record.sweep],
        });
    }

    reports
}

fn file_chunk_peer_status(
    chunk_result: &std::result::Result<Option<ant_protocol::DataChunk>, Error>,
) -> FileChunkPeerStatus {
    match chunk_result {
        Ok(Some(chunk)) => FileChunkPeerStatus::Found {
            bytes: chunk.content.len(),
        },
        Ok(None) => FileChunkPeerStatus::NotFound,
        Err(Error::Timeout(e)) => FileChunkPeerStatus::Timeout { message: e.clone() },
        Err(Error::Network(e)) => FileChunkPeerStatus::NetworkError { message: e.clone() },
        Err(e) => FileChunkPeerStatus::Error {
            message: e.to_string(),
        },
    }
}

/// Gas used by one `pay_for_quotes` transaction that packs up to
/// `UPLOAD_WAVE_SIZE` (quote_hash, rewards_address, amount) entries.
///
/// A wave's payment flattens every chunk's close-group quotes into a
/// single EVM call, so the dominant cost is the SSTOREs for each entry plus
/// the base tx overhead. On Arbitrum that is roughly
/// `21_000 + 64 × (20_000 + small)` ≈ 1.3M; we round up to 1.5M as a
/// conservative per-wave upper bound.
const GAS_PER_WAVE_TX: u128 = 1_500_000;

/// Gas used by one merkle batch payment transaction.
///
/// One on-chain tx per merkle sub-batch, but each tx verifies a merkle tree
/// and posts a pool commitment, so budget higher than a plain transfer.
const GAS_PER_MERKLE_TX: u128 = 500_000;

/// Advisory gas price (wei/gas) used to turn the gas estimate into an ETH
/// figure when no live gas oracle is consulted.
///
/// Arbitrum One typically settles around 0.1 gwei on quiet blocks; we use
/// that as the default so the CLI prints a sensible order-of-magnitude
/// number. Users should treat the reported gas cost as an estimate, not a
/// commitment — real gas is bid at submission time.
const ARBITRUM_GAS_PRICE_WEI: u128 = 100_000_000;

/// Extra headroom percentage for disk space check.
///
/// Encrypted chunks are slightly larger than the source data due to padding
/// and self-encryption overhead. We require file_size + 10% free space in
/// the temp directory to account for this.
const DISK_SPACE_HEADROOM_PERCENT: u64 = 10;

/// Temporary on-disk buffer for encrypted chunks.
///
/// During file encryption, chunks are written to a temp directory so that
/// only their 32-byte addresses stay in memory. At upload time chunks are
/// read back one wave at a time, keeping peak RAM at ~`UPLOAD_WAVE_SIZE × 4 MB`.
/// Grace period (in seconds) before a spill dir is eligible for stale cleanup.
///
/// This is a small TOCTOU guard covering the sub-millisecond window inside
/// [`ChunkSpill::new`] between `create_dir` and `try_lock_exclusive`. Once a
/// dir is older than this and its lockfile is releasable, the owning process
/// is gone and the dir is safe to reap — regardless of how old it is.
///
/// The previous policy waited 24 h before reaping any orphan, which meant
/// that any non-graceful exit (SIGKILL, kernel OOM, panic abort) leaked its
/// spill dir until the next day's upload — and on a host being restart-looped
/// by systemd, orphans could fill the disk well within that window.
const SPILL_STALE_GRACE_SECS: u64 = 30;

/// Prefix for spill directory names to distinguish from user files.
const SPILL_DIR_PREFIX: &str = "spill_";

/// Lockfile name inside each spill dir to signal active use.
const SPILL_LOCK_NAME: &str = ".lock";

struct ChunkSpill {
    /// Directory holding spilled chunk files (named by hex address).
    dir: PathBuf,
    /// Lockfile held for the lifetime of this spill (prevents stale cleanup).
    _lock: std::fs::File,
    /// Deduplicated list of chunk addresses.
    addresses: Vec<[u8; 32]>,
    /// Tracks seen addresses for deduplication.
    seen: HashSet<[u8; 32]>,
    /// Byte size per spilled chunk address.
    sizes: HashMap<[u8; 32], u64>,
    /// Running total of unique chunk byte sizes (for average-size calculation).
    total_bytes: u64,
}

impl ChunkSpill {
    /// Return the parent directory for all spill dirs: `<data_dir>/spill/`.
    fn spill_root() -> Result<PathBuf> {
        use crate::config;
        let root = config::data_dir()
            .map_err(|e| Error::Config(format!("cannot determine data dir for spill: {e}")))?
            .join("spill");
        Ok(root)
    }

    /// Create a new spill directory under `<data_dir>/spill/`.
    ///
    /// Directory name is `spill_<timestamp>_<random>` so orphans can be
    /// identified by prefix and cleaned up by age. A lockfile inside the
    /// dir prevents concurrent cleanup from deleting an active spill.
    fn new() -> Result<Self> {
        let root = Self::spill_root()?;
        std::fs::create_dir_all(&root)?;

        // Clean up stale spill dirs from previous crashed runs.
        Self::cleanup_stale(&root);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let unique: u64 = rand::random();
        let dir = root.join(format!("{SPILL_DIR_PREFIX}{now}_{unique}"));
        std::fs::create_dir(&dir)?;

        // Create and hold a lockfile for the lifetime of this spill.
        // cleanup_stale() will skip dirs with locked files.
        let lock_path = dir.join(SPILL_LOCK_NAME);
        let lock_file = std::fs::File::create(&lock_path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("failed to create spill lockfile: {e}"),
            ))
        })?;
        lock_file.try_lock_exclusive().map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("failed to lock spill lockfile: {e}"),
            ))
        })?;

        Ok(Self {
            dir,
            _lock: lock_file,
            addresses: Vec::new(),
            seen: HashSet::new(),
            sizes: HashMap::new(),
            total_bytes: 0,
        })
    }

    /// Clean up stale spill directories. Best-effort, errors are logged.
    ///
    /// A spill dir is reaped when:
    /// 1. Its name starts with `SPILL_DIR_PREFIX` (ignores unrelated files)
    /// 2. It is an actual directory, not a symlink (prevents symlink attacks)
    /// 3. Its timestamp is older than `SPILL_STALE_GRACE_SECS` (TOCTOU guard)
    /// 4. Its lockfile is releasable — i.e. no live process holds it
    ///
    /// The lockfile is the primary correctness gate: a releasable lock means
    /// the owning `ChunkSpill` has been dropped or the process is gone, so
    /// the dir is fair game. The grace period covers only the brief window
    /// inside [`Self::new`] between `create_dir` and `try_lock_exclusive`.
    ///
    /// Safe to call concurrently from multiple processes.
    fn cleanup_stale(root: &Path) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now == 0 {
            // Clock is broken (before Unix epoch). Skip cleanup to avoid
            // misidentifying dirs as stale.
            warn!("System clock before Unix epoch, skipping spill cleanup");
            return;
        }

        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only process dirs with our prefix.
            let suffix = match name_str.strip_prefix(SPILL_DIR_PREFIX) {
                Some(s) => s,
                None => continue,
            };

            // Parse timestamp: "spill_<timestamp>_<random>"
            let timestamp: u64 = match suffix.split('_').next().and_then(|s| s.parse().ok()) {
                Some(ts) => ts,
                None => continue,
            };

            if now.saturating_sub(timestamp) < SPILL_STALE_GRACE_SECS {
                continue;
            }

            // Safety: only delete actual directories, not symlinks.
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if !file_type.is_dir() {
                continue;
            }

            let path = entry.path();

            // Check lockfile: if locked, the dir is in active use -- skip it.
            let lock_path = path.join(SPILL_LOCK_NAME);
            if let Ok(lock_file) = std::fs::File::open(&lock_path) {
                use fs2::FileExt;
                if lock_file.try_lock_exclusive().is_err() {
                    // Lock held by another process -- dir is active.
                    debug!("Skipping active spill dir: {}", path.display());
                    continue;
                }
                // We acquired the lock, so no one else holds it.
                // Drop it before deleting.
                drop(lock_file);
            }

            info!("Cleaning up stale spill dir: {}", path.display());
            if let Err(e) = std::fs::remove_dir_all(&path) {
                warn!("Failed to clean up stale spill dir {}: {e}", path.display());
            }
        }
    }

    /// Run stale spill cleanup. Call at client startup or periodically.
    #[allow(dead_code)]
    pub(crate) fn run_cleanup() {
        if let Ok(root) = Self::spill_root() {
            Self::cleanup_stale(&root);
        }
    }

    /// Write one encrypted chunk to disk and record its address.
    ///
    /// Deduplicates by content address: if the same chunk was already
    /// spilled, the write and accounting are skipped. This prevents
    /// double-uploads and inflated quoting metrics.
    fn push(&mut self, content: &[u8]) -> Result<()> {
        let address = compute_address(content);
        if !self.seen.insert(address) {
            return Ok(());
        }
        let path = self.dir.join(hex::encode(address));
        std::fs::write(&path, content)?;
        let content_len = content.len() as u64;
        self.sizes.insert(address, content_len);
        self.total_bytes += content_len;
        self.addresses.push(address);
        Ok(())
    }

    /// Number of chunks stored.
    fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Total bytes of all spilled chunks.
    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Address and byte-size pairs for all spilled chunks.
    fn chunk_entries(&self) -> Result<Vec<([u8; 32], u64)>> {
        self.addresses
            .iter()
            .map(|address| {
                self.sizes
                    .get(address)
                    .copied()
                    .map(|size| (*address, size))
                    .ok_or_else(|| {
                        Error::Storage(format!(
                            "missing size for spilled chunk {}",
                            hex::encode(address)
                        ))
                    })
            })
            .collect()
    }

    /// Read a single chunk back from disk by address.
    fn read_chunk(&self, address: &[u8; 32]) -> Result<Bytes> {
        let path = self.dir.join(hex::encode(address));
        let data = std::fs::read(&path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("reading spilled chunk {}: {e}", hex::encode(address)),
            ))
        })?;
        Ok(Bytes::from(data))
    }

    /// Read the bodies for `addresses` back from disk, in the given order.
    fn read_chunks(&self, addresses: &[[u8; 32]]) -> Result<Vec<Bytes>> {
        addresses.iter().map(|addr| self.read_chunk(addr)).collect()
    }

    /// Read every spilled body back, in insertion order.
    fn read_all_chunks(&self) -> Result<Vec<Bytes>> {
        self.read_chunks(&self.addresses)
    }

    /// Clean up the spill directory.
    fn cleanup(&self) {
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            warn!(
                "Failed to clean up chunk spill dir {}: {e}",
                self.dir.display()
            );
        }
    }
}

impl Drop for ChunkSpill {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
fn cached_merkle_covers_addresses(
    cached: &MerkleBatchPaymentResult,
    addresses: &[[u8; 32]],
) -> bool {
    addresses
        .iter()
        .all(|addr| cached.proofs.contains_key(addr))
}

/// Split `addresses` into `(to_store, missing_proof)`: those that have a merkle
/// proof in `proofs`, and those that don't.
///
/// A partial [`MerkleBatchPaymentResult`] (from a `pay_for_merkle_multi_batch`
/// where a later sub-batch failed) carries proofs only for the sub-batches that
/// both settled AND produced proofs, so chunks reach the upload path with no
/// proof. Usually that means they were never paid for, but not always: a
/// sub-batch settles on-chain before its proofs are generated. `upload_merkle_from_spill` reports those as failed via
/// [`Error::PartialUpload`] rather than aborting the whole file. Order within
/// each group follows `addresses`.
fn partition_addresses_by_proof(
    addresses: &[[u8; 32]],
    proofs: &HashMap<[u8; 32], Vec<u8>>,
) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    addresses
        .iter()
        .copied()
        .partition(|addr| proofs.contains_key(addr))
}

/// The clause naming chunks that reached the store path with no merkle proof,
/// or `None` when every chunk had one.
///
/// `payment_refusal` is the storers' verdict when one stopped this upload's
/// own payment. It goes last, and is scoped before it is quoted: the refusal's
/// own wording says nothing was charged, which is true of the sub-batch it
/// refused and false of an upload whose earlier sub-batches already settled —
/// the CLI prints that spend on the same line. Mirrors
/// [`settlement_refusal_after_paid_waves`], which does the same job for the
/// single-node wave path.
///
/// Says only that the proof is absent, never that the chunk went unpaid: a
/// sub-batch settles on-chain before its proofs are generated, so a
/// proof-generation failure leaves chunks that were charged for and still have
/// no proof.
fn proofless_clause(proofless_count: usize, payment_refusal: Option<&str>) -> Option<String> {
    if proofless_count == 0 {
        return None;
    }
    Some(match payment_refusal {
        Some(refusal) => format!(
            "{proofless_count} chunk(s) have no merkle proof because storers refused this \
             client's settlement version during payment. That refusal covers those chunks; \
             any spend reported here settled for earlier sub-batches. {refusal}"
        ),
        None => format!("{proofless_count} chunk(s) have no merkle proof"),
    })
}

/// The `PartialUpload` reason for a merkle upload that ends with failed chunks.
///
/// Chunks with no proof were never attempted, so folding them into "short of
/// quorum after N attempts" reports a failure they did not have and, when a
/// settlement refusal stopped the payment, replaces the one instruction that
/// makes the next attempt work. The two groups are reported separately so the
/// counts still add up to `failed_count`.
fn merkle_partial_reason(
    failed_count: usize,
    proofless_count: usize,
    total_attempts: usize,
    payment_refusal: Option<&str>,
) -> String {
    let quorum = |n: usize| format!("{n} chunk(s) short of quorum after {total_attempts} attempts");
    match proofless_clause(proofless_count, payment_refusal) {
        None => quorum(failed_count),
        // Saturating because the proof-less chunks are a subset of the failed
        // ones by construction; if that ever stops holding, under-reporting the
        // shortfall beats an underflow panic on the error path.
        Some(proofless) => match failed_count.saturating_sub(proofless_count) {
            0 => proofless,
            short => format!("{}; {proofless}", quorum(short)),
        },
    }
}

/// The `PartialUpload` reason for a merkle upload that a store failure aborted.
///
/// The abort is the immediate cause and leads, but chunks that arrived with no
/// proof are a second, independent failure with its own remedy. Reporting only
/// the abort leaves that remedy in the per-chunk messages, which the CLI does
/// not print.
fn merkle_fatal_reason(
    abort: &str,
    proofless_count: usize,
    payment_refusal: Option<&str>,
) -> String {
    match proofless_clause(proofless_count, payment_refusal) {
        Some(proofless) => format!("{abort}; {proofless}"),
        None => abort.to_string(),
    }
}

/// Build a `PartialUpload` after a fatal merkle store error, with accurate
/// counts.
///
/// A fatal abort can leave chunks in three states: confirmed stored (in
/// `stored_addresses`), known-failed (in `known_failed` — missing proofs, the
/// quorum shortfalls and the fatal chunk seen so far), and "in flight when the
/// abort hit" (neither). Rather than trust the helpers to enumerate the last
/// group, this derives the failed set authoritatively as *every* `addresses`
/// entry not in `stored_addresses`, preferring a known per-chunk message and
/// falling back to the fatal `reason`. That guarantees
/// `stored_count + failed_count` accounts for the whole file — fixing the
/// under-reporting where a fatal wave could surface `failed_count = 0` and omit
/// same-pass successes.
fn partial_upload_after_fatal(
    addresses: &[[u8; 32]],
    stored_addresses: Vec<[u8; 32]>,
    stored_count: usize,
    total_chunks: usize,
    known_failed: Vec<([u8; 32], String)>,
    spend: PartialUploadSpend,
    reason: String,
) -> Error {
    let stored_set: HashSet<[u8; 32]> = stored_addresses.iter().copied().collect();
    let mut failed_map: HashMap<[u8; 32], String> = HashMap::new();
    for (addr, msg) in known_failed {
        if !stored_set.contains(&addr) {
            failed_map.entry(addr).or_insert(msg);
        }
    }
    for addr in addresses {
        if !stored_set.contains(addr) {
            failed_map.entry(*addr).or_insert_with(|| reason.clone());
        }
    }
    let failed: Vec<([u8; 32], String)> = failed_map.into_iter().collect();
    let failed_count = failed.len();
    Error::PartialUpload {
        stored: stored_addresses,
        stored_count,
        failed,
        failed_count,
        total_chunks,
        spend: Box::new(spend),
        reason,
    }
}

/// Require every sub-batch of a *resumable* merkle finalize to be paid.
///
/// A [`MerkleFinalizeResume`] re-drives storage against the proofs folded at
/// finalize time and accepts no new payment material, so a chunk whose
/// sub-batch was never paid could never acquire a proof on resume: every
/// [`Client::finalize_resume`] call would report it as missing-proof again and
/// the handle would never drain to [`FinalizeOutcome::Complete`]. Rejecting
/// partial payment up front keeps resume handles always drainable. A caller
/// that intends to pay only some sub-batches must use the non-resumable
/// [`Client::finalize_upload_merkle_multi`], which surfaces the unpaid chunks
/// through [`Error::PartialUpload`] (ADR-0003).
fn require_fully_paid_for_resumable(winner_pool_hashes: &[Option<[u8; 32]>]) -> Result<()> {
    let unpaid = winner_pool_hashes.iter().filter(|h| h.is_none()).count();
    if unpaid > 0 {
        return Err(Error::Payment(format!(
            "{unpaid}/{} sub-batch(es) unpaid: the resumable finalize requires every \
             sub-batch to be paid, because a resume handle cannot acquire proofs for \
             unpaid chunks and would never drain to Complete. Pay every sub-batch, or \
             use finalize_upload_merkle_multi() to finalize a partial payment (its \
             unpaid chunks are reported through PartialUpload).",
            winner_pool_hashes.len()
        )));
    }
    Ok(())
}

/// Fold the per-batch winner hashes of an external merkle upload into one
/// combined payment receipt.
///
/// Validates that `winner_pool_hashes` aligns with `prepared_batches` (one
/// entry per batch, in order), requires at least one paid batch, finalizes
/// each paid batch, and merges the receipts the way the wallet path folds
/// its sub-batch payments. Unpaid (`None`) batches contribute no proofs, so
/// the store phase reports their chunks through [`Error::PartialUpload`]
/// (ADR-0003) — the resumable path rejects them up front instead
/// ([`require_fully_paid_for_resumable`]).
fn fold_external_merkle_payments(
    prepared_batches: Vec<PreparedMerkleBatch>,
    winner_pool_hashes: Vec<Option<[u8; 32]>>,
) -> Result<MerkleBatchPaymentResult> {
    let batch_count = prepared_batches.len();
    if winner_pool_hashes.len() != batch_count {
        return Err(Error::Payment(format!(
            "Expected {batch_count} winner pool hash entries (one per \
             prepared sub-batch), got {}.",
            winner_pool_hashes.len()
        )));
    }

    let mut paid = Vec::with_capacity(batch_count);
    let mut unpaid_batches = 0usize;
    for (batch, hash) in prepared_batches.into_iter().zip(winner_pool_hashes) {
        match hash {
            Some(h) => paid.push(finalize_merkle_batch(batch, h)?),
            None => unpaid_batches += 1,
        }
    }
    if paid.is_empty() {
        return Err(Error::Payment(
            "No merkle sub-batch was paid — nothing to finalize. \
             Pay at least one batch or drop the prepared upload."
                .to_string(),
        ));
    }
    if unpaid_batches > 0 {
        warn!(
            "External merkle finalize: {unpaid_batches}/{batch_count} sub-batch(es) \
             unpaid; their chunks will be reported as failed"
        );
    }
    Ok(merge_merkle_batch_results(paid))
}

/// Assemble the outcome of one external-signer merkle store pass into
/// [`FinalizeOutcome`]. Pure (no `self`/network) so the resume-handoff contract
/// is unit-testable.
///
/// `Ok` from the store becomes [`FinalizeOutcome::Complete`]. A recoverable
/// [`Error::PartialUpload`] becomes [`FinalizeOutcome::Partial`], moving the
/// retained spill and proofs into a [`MerkleFinalizeResume`] whose
/// `unstored_addresses` are the failed chunks (to store next) and whose
/// `stored_addresses` is the cumulative stored set (carried forward as the next
/// attempt's already-stored input). Any other error is fatal and propagates
/// unchanged.
fn assemble_merkle_finalize_outcome(
    store_result: Result<(usize, String, u128, WaveAggregateStats)>,
    data_map: DataMap,
    data_map_address: Option<[u8; 32]>,
    total_chunks: usize,
    chunk_store: ExternalChunkStore,
    batch_result: MerkleBatchPaymentResult,
) -> Result<FinalizeOutcome> {
    match store_result {
        Ok((chunks_stored, _storage_cost, _gas_cost, stats)) => {
            info!("External-signer merkle upload finalized: {chunks_stored} chunks stored");
            Ok(FinalizeOutcome::Complete(FileUploadResult {
                data_map,
                chunks_stored,
                chunks_failed: 0,
                total_chunks,
                payment_mode_used: PaymentMode::Merkle,
                // The external signer pays on-chain out-of-band, so the spend
                // is unknown to the library here.
                storage_cost_atto: "0".into(),
                gas_cost_wei: 0,
                data_map_address,
                chunk_attempts_total: stats.chunk_attempts_total,
                store_durations_ms: stats.store_durations_ms,
                retries_histogram: stats.retries_histogram,
                envelope: None,
            }))
        }
        Err(Error::PartialUpload {
            stored,
            stored_count,
            failed,
            failed_count,
            spend,
            ..
        }) => {
            // Recoverable: retain the spill and the already-signed proofs so the
            // caller can drain the remainder against the same payment.
            let unstored_addresses: Vec<[u8; 32]> = failed.iter().map(|(addr, _)| *addr).collect();
            let result = FileUploadResult {
                data_map: data_map.clone(),
                chunks_stored: stored_count,
                chunks_failed: failed_count,
                total_chunks,
                payment_mode_used: PaymentMode::Merkle,
                storage_cost_atto: spend.storage_cost_atto.clone(),
                gas_cost_wei: spend.gas_cost_wei,
                data_map_address,
                // Per-attempt store telemetry is not carried on a partial.
                chunk_attempts_total: 0,
                store_durations_ms: Vec::new(),
                retries_histogram: [0; 4],
                envelope: None,
            };
            let resume = MerkleFinalizeResume {
                data_map,
                data_map_address,
                total_chunks,
                chunk_store,
                unstored_addresses,
                batch_result,
                // Cumulative stored set (already-stored + stored this pass),
                // carried forward as the next attempt's already-stored input.
                stored_addresses: stored,
            };
            Ok(FinalizeOutcome::Partial {
                result,
                resume: FinalizeResume::Merkle(Box::new(resume)),
            })
        }
        Err(e) => Err(e),
    }
}

/// What an outside payer's payment came to once its paid quotes were read
/// back ([`Client::read_back_outside_payment`]).
struct OutsidePaymentReadBack {
    /// The chunks to store.
    paid: Vec<PaidChunk>,
    /// The chunks set aside, never to be sent, each with why: the vault had
    /// recorded its paid quote for another payment first.
    unpaid: Vec<([u8; 32], String)>,
    /// The payment intent's total, less the payments the vault skipped.
    storage_cost_atto: String,
    /// Why the upload can't complete on this payment, if any chunk was set
    /// aside.
    reason: Option<String>,
}

/// Assemble the outcome of one wave-batch external store pass into
/// [`FinalizeOutcome`]. Pure (no `self`/network) so the resume-handoff contract
/// is unit-testable.
///
/// `retained` maps every paid chunk's address to its [`PaidChunk`] (body +
/// proof + PUT targets). If [`WaveResult`] reports no failures the result is
/// [`FinalizeOutcome::Complete`]; otherwise the failed chunks' [`PaidChunk`]s
/// are pulled out of `retained` into a [`WaveFinalizeResume`] so the caller can
/// re-store just those against the same payment — the store never returns an
/// `Err` for a partial, so this function is infallible. `occupied` lists the
/// chunks this payment can't store (their failures are in `wave_result` too,
/// and their paid chunks are not in `retained`); the handle carries the list.
#[allow(clippy::too_many_arguments)]
fn assemble_wave_finalize_outcome(
    wave_result: WaveResult,
    mut retained: HashMap<[u8; 32], PaidChunk>,
    occupied: Vec<([u8; 32], String)>,
    data_map: DataMap,
    data_map_address: Option<[u8; 32]>,
    total_chunks: usize,
    already_stored_count: usize,
    storage_cost_atto: String,
) -> FinalizeOutcome {
    let stored_count = already_stored_count + wave_result.stored.len();
    if wave_result.failed.is_empty() {
        info!("External-signer upload finalized: {stored_count} chunks stored");
        let mut stats = WaveAggregateStats::default();
        stats.absorb(&wave_result);
        return FinalizeOutcome::Complete(FileUploadResult {
            data_map,
            chunks_stored: stored_count,
            chunks_failed: 0,
            total_chunks,
            payment_mode_used: PaymentMode::Single,
            // Storage spend is known from the payment intent; gas is paid by the
            // external signer out-of-band (unknown here).
            storage_cost_atto,
            gas_cost_wei: 0,
            data_map_address,
            chunk_attempts_total: stats.chunk_attempts_total,
            store_durations_ms: stats.store_durations_ms,
            retries_histogram: stats.retries_histogram,
            envelope: None,
        });
    }

    // Recoverable: pull the already-paid chunks that still need storing back out
    // so the caller can re-store them against the same payment.
    let failed_count = wave_result.failed.len();
    let failed_paid_chunks: Vec<PaidChunk> = wave_result
        .failed
        .iter()
        .filter_map(|(addr, _)| retained.remove(addr))
        .collect();
    let result = FileUploadResult {
        data_map: data_map.clone(),
        chunks_stored: stored_count,
        chunks_failed: failed_count,
        total_chunks,
        payment_mode_used: PaymentMode::Single,
        storage_cost_atto: storage_cost_atto.clone(),
        gas_cost_wei: 0,
        data_map_address,
        // Per-attempt store telemetry is not carried on a partial.
        chunk_attempts_total: 0,
        store_durations_ms: Vec::new(),
        retries_histogram: [0; 4],
        envelope: None,
    };
    let resume = WaveFinalizeResume {
        data_map,
        data_map_address,
        total_chunks,
        stored_count,
        failed_paid_chunks,
        occupied,
        storage_cost_atto,
        envelope: None,
    };
    FinalizeOutcome::Partial {
        result,
        resume: FinalizeResume::Wave(Box::new(resume)),
    }
}

/// One wave's contribution to a single-node upload, distilled from its
/// `batch_upload_chunks_with_events` result.
#[derive(Debug)]
#[cfg(test)]
struct SingleWaveOutcome {
    /// Addresses confirmed stored in this wave.
    stored: Vec<[u8; 32]>,
    /// Chunks that failed after retries in this wave.
    failed: Vec<([u8; 32], String)>,
    /// Storage cost paid on-chain for this wave, in atto-tokens.
    storage_atto: Amount,
    /// Gas paid on-chain for this wave, in wei.
    gas_wei: u128,
    /// Per-wave store/retry statistics. Empty for a quorum-short wave, whose
    /// `PartialUpload` carries no stats.
    stats: WaveAggregateStats,
}

/// Fold one wave's batch-upload result for the single-node path.
///
/// A `PartialUpload` (chunks short of quorum after retries) is **recoverable**:
/// its stored/failed chunks and on-chain spend are returned so the caller
/// records them and continues to the next wave, making the file make maximum
/// progress exactly like `upload_merkle_from_spill`. Every other error is **fatal**
/// (wallet/payment-infrastructure failures, missing proofs, spill reads) and is
/// returned via `Err` to abort the file. Because `UPLOAD_WAVE_SIZE ==
/// PAYMENT_WAVE_SIZE`, each batch call is exactly one payment wave, so folding a
/// `PartialUpload` leaves nothing un-attempted within the wave.
#[cfg(test)]
fn fold_single_wave(
    result: Result<(Vec<[u8; 32]>, String, u128, WaveAggregateStats)>,
) -> Result<SingleWaveOutcome> {
    match result {
        Ok((stored, storage, gas, stats)) => Ok(SingleWaveOutcome {
            stored,
            failed: Vec::new(),
            storage_atto: storage.parse().unwrap_or(Amount::ZERO),
            gas_wei: gas,
            stats,
        }),
        Err(Error::PartialUpload {
            stored,
            failed,
            spend,
            ..
        }) => Ok(SingleWaveOutcome {
            stored,
            failed,
            storage_atto: spend.storage_cost_atto.parse().unwrap_or(Amount::ZERO),
            gas_wei: spend.gas_cost_wei,
            stats: WaveAggregateStats::default(),
        }),
        Err(e) => Err(e),
    }
}

/// Shape a corroborated settlement refusal that landed on a wave **after** an
/// earlier wave had already paid and stored.
///
/// The refusal is terminal for this build, but by wave two or later it is no
/// longer true that nothing was charged: the single-node path pays each wave
/// before storing it, so the earlier waves' spend has settled on-chain. Bare
/// `ClientUpdateRequired` would report the upload as costing nothing and drop
/// the stored set a resume needs, so the refusal is surfaced as a
/// `PartialUpload` carrying the real spend and the stored chunks, with the
/// storer's upgrade instruction kept in the reason. Every remaining chunk is
/// listed as failed: none of it was quoted, let alone paid for.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn settlement_refusal_after_paid_waves(
    refusal: &str,
    wave_num: usize,
    wave_count: usize,
    stored_addresses: Vec<[u8; 32]>,
    total_stored: usize,
    remaining: &[[u8; 32]],
    total_chunks: usize,
    total_storage: Amount,
    total_gas: u128,
) -> Error {
    let remaining_count = remaining.len();
    let refused_note = format!(
        "not quoted: storers refused this client's settlement version at wave \
         {wave_num}/{wave_count}"
    );
    let failed: Vec<([u8; 32], String)> = remaining
        .iter()
        .map(|addr| (*addr, refused_note.clone()))
        .collect();
    Error::PartialUpload {
        stored: stored_addresses,
        stored_count: total_stored,
        failed,
        failed_count: remaining_count,
        total_chunks,
        spend: Box::new(PartialUploadSpend {
            storage_cost_atto: total_storage.to_string(),
            gas_cost_wei: total_gas,
        }),
        reason: format!(
            "storers refused this client's settlement version at wave {wave_num}/{wave_count}: \
             the {total_stored} chunk(s) in earlier wave(s) were already paid for and stored, \
             and the remaining {remaining_count} chunk(s) were neither quoted nor paid. {refusal}"
        ),
    }
}

/// Check that the spill directory has enough free space for the spilled chunks.
///
/// `file_size` is the source file's byte count. We require
/// `file_size + 10%` free space to account for self-encryption overhead.
fn check_disk_space_for_spill(file_size: u64) -> Result<()> {
    let spill_root = ChunkSpill::spill_root()?;

    // Ensure the root exists so fs2 can query it.
    std::fs::create_dir_all(&spill_root)?;

    let available = fs2::available_space(&spill_root).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!(
                "failed to query disk space on {}: {e}",
                spill_root.display()
            ),
        ))
    })?;

    // Use integer arithmetic to avoid f64 precision loss on large file sizes.
    let headroom = file_size / DISK_SPACE_HEADROOM_PERCENT;
    let required = file_size.saturating_add(headroom);

    if available < required {
        let avail_mb = available / (1024 * 1024);
        let req_mb = required / (1024 * 1024);
        return Err(Error::InsufficientDiskSpace(format!(
            "need ~{req_mb} MB in spill dir ({}) but only {avail_mb} MB available",
            spill_root.display()
        )));
    }

    debug!(
        "Disk space check passed: {available} bytes available, {required} bytes required (spill: {})",
        spill_root.display()
    );
    Ok(())
}

fn usable_memory_bytes() -> Option<u64> {
    let mut system = sysinfo::System::new();
    system.refresh_memory();

    let available_memory = system.available_memory();
    let free_memory = system.free_memory();
    let used_memory = system.used_memory();
    let total_memory = system.total_memory();
    let unused_memory = total_memory.saturating_sub(used_memory);

    let mut usable = [available_memory, free_memory, unused_memory]
        .into_iter()
        .filter(|bytes| *bytes > 0)
        .max();

    let cgroup_free_memory = system
        .cgroup_limits()
        .filter(|limits| limits.total_memory > 0)
        .map(|limits| limits.free_memory);
    if let Some(cgroup_free_memory) = cgroup_free_memory {
        usable = Some(usable.unwrap_or(u64::MAX).min(cgroup_free_memory));
    }

    debug!(
        available_memory,
        free_memory,
        used_memory,
        total_memory,
        cgroup_free_memory,
        usable_memory = ?usable,
        "Detected usable memory for stream decrypt batch sizing"
    );

    usable
}

fn stream_decrypt_batch_memory_cap(usable_memory_bytes: u64) -> usize {
    let budget = usable_memory_bytes / DOWNLOAD_STREAM_BATCH_MEMORY_BUDGET_DIVISOR;
    let estimated_bytes_per_chunk = (self_encryption::MAX_CHUNK_SIZE as u64)
        .saturating_mul(DOWNLOAD_STREAM_BATCH_BYTES_PER_CHUNK_MULTIPLIER)
        .max(1);
    let cap = (budget / estimated_bytes_per_chunk).max(1);

    usize::try_from(cap).unwrap_or(usize::MAX)
}

fn adaptive_stream_decrypt_batch_size(
    total_chunks: usize,
    fetch_cap: usize,
    configured_batch_floor: usize,
    usable_memory_bytes: Option<u64>,
) -> usize {
    let fetch_target = fetch_cap
        .max(1)
        .saturating_mul(DOWNLOAD_STREAM_BATCH_FETCH_MULTIPLIER);
    let requested = match usable_memory_bytes {
        Some(bytes) => {
            let memory_cap = stream_decrypt_batch_memory_cap(bytes);
            configured_batch_floor
                .max(fetch_target)
                .max(1)
                .min(memory_cap)
        }
        None => configured_batch_floor.max(1),
    };

    requested.min(total_chunks.max(1)).max(1)
}

/// The data map `path` encrypts to, as an upload of it computes it, without
/// storing anything. Self-encryption is deterministic, so comparing it with
/// a published or revealed data map checks that a local file is the one
/// uploaded.
///
/// # Errors
///
/// Returns an error if the file can't be read or encrypted.
pub async fn file_data_map(path: &Path) -> Result<DataMap> {
    let (mut chunks, data_map, handle) = spawn_file_encryption(path.to_path_buf())?;
    while chunks.recv().await.is_some() {}
    handle
        .await
        .map_err(|e| Error::Encryption(format!("encryption task panicked: {e}")))?
        .map_err(|e| Error::Encryption(format!("encryption failed: {e}")))?;
    data_map
        .await
        .map_err(|_| Error::Encryption("no DataMap from encryption thread".to_string()))
}

/// Payment information for external signing — either wave-batch or merkle.
// ADR-0004 added the signed commitment fields (`committed_key_count`,
// `commitment_pin`) to the merkle candidate quotes carried inside
// `PreparedMerkleBatch`, which grew the `Merkle` variant past the
// `large_enum_variant` threshold. This enum is constructed one-off per payment
// (never held in bulk collections), so the size delta is harmless; allow it
// rather than box a field on the security-sensitive merkle-finalize path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ExternalPaymentInfo {
    /// Wave-batch: individual (quote_hash, rewards_address, amount) tuples.
    WaveBatch {
        /// Chunks ready for payment (needed for finalize).
        prepared_chunks: Vec<PreparedChunk>,
        /// Payment intent for external signing.
        payment_intent: PaymentIntent,
    },
    /// Merkle: one on-chain payment call per prepared sub-batch.
    Merkle {
        /// The prepared merkle sub-batches, in address order (public fields
        /// sent to the frontend, private fields stay in Rust). The external
        /// signer submits one `payForMerkleTree` transaction per batch;
        /// finalize takes one winner hash per batch in the same order
        /// (ADR-0003). A fresh upload below `MAX_LEAVES` chunks prepares as
        /// exactly one batch, so single-payment consumers keep working
        /// until they exceed it.
        prepared_batches: Vec<PreparedMerkleBatch>,
        /// Bodies of the chunks that still need upload, held in the
        /// encryption spill on disk — NOT resident in memory (ADR-0003).
        chunk_store: ExternalChunkStore,
        /// Chunk addresses that still need upload after the preflight check.
        chunk_addresses: Vec<[u8; 32]>,
    },
}

/// Opaque on-disk store of the chunk bodies carried by a prepared external
/// merkle upload.
///
/// Wraps the encryption spill: bodies stay on disk from prepare until
/// finalize reads them back ≤ store-cap at a time, so peak RAM for the
/// external path matches the wallet path's ~256 MB bound instead of the file
/// size (ADR-0003). The spill directory lives exactly as long as this value:
/// dropping the `PreparedUpload` (e.g. a consumer's session TTL expiring or
/// an explicit cancel) removes it from disk.
pub struct ExternalChunkStore(ChunkSpill);

impl ExternalChunkStore {
    fn from_spill(spill: ChunkSpill) -> Self {
        Self(spill)
    }

    fn spill(&self) -> &ChunkSpill {
        &self.0
    }
}

impl std::fmt::Debug for ExternalChunkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalChunkStore")
            .field("chunks", &self.0.len())
            .field("bytes", &self.0.total_bytes())
            .finish()
    }
}

/// What the payment whose outcome is unknown pays, from its prepared plans:
/// zero for a Merkle payment or if the plans are missing.
fn unresolved_payment_amount(state: &crate::data::client::upload_state::UploadState) -> Amount {
    if state
        .pending_payment
        .as_ref()
        .is_none_or(|attempt| attempt.merkle)
    {
        return Amount::ZERO;
    }
    state
        .pending_plans()
        .map(|plans| {
            plans.iter().fold(Amount::ZERO, |sum, plan| {
                sum.saturating_add(plan.payment.total_amount())
            })
        })
        .unwrap_or(Amount::ZERO)
}

/// An envelope upload's checkpoint scope: its choices
/// ([`EnvelopeOptions::scope`]) and its payer (`payer`:
/// [`UploadPayer::checkpoint_scope`], or the wallet's address), so only the
/// same payer resumes it, reusing its salt and the envelope's payment. The
/// choices end where their msgpack ends, so the payer can simply follow.
fn envelope_checkpoint_scope(options: &EnvelopeOptions, payer: &[u8]) -> Vec<u8> {
    let mut scope = options.scope();
    scope.extend_from_slice(payer);
    scope
}

/// What names an upload's checkpoint ([`open_upload_checkpoint`]): the
/// payment network and the content records, with an envelope upload's scope
/// (`envelope`, [`envelope_checkpoint_scope`], which names its payer), or
/// else an outside payer's [`UploadPayer::checkpoint_scope`] (`payer`). A
/// wallet upload without an envelope has neither, and shares the checkpoint
/// of its records as before.
fn upload_checkpoint_scope(
    network: &ant_protocol::evm::Network,
    records: &[([u8; 32], u64)],
    envelope: Option<&[u8]>,
    payer: Option<&[u8]>,
) -> Result<Vec<u8>> {
    match (envelope, payer) {
        (Some(envelope), _) => rmp_serde::to_vec(&(network, records, envelope)),
        (None, Some(payer)) => rmp_serde::to_vec(&(network, records, "payer", payer)),
        (None, None) => rmp_serde::to_vec(&(network, records)),
    }
    .map_err(|e| Error::Serialization(e.to_string()))
}

/// Open the checkpoint for uploading `records` on `network`: its path, the
/// lock held while the upload runs, and the state an earlier, interrupted
/// attempt saved (`None` if there was none).
///
/// An envelope upload's checkpoint is scoped by its content records, its
/// envelope choices and its payer (`envelope`,
/// [`envelope_checkpoint_scope`]), not by the envelope's address, which a
/// private envelope's random salt changes: the salt is saved next to the
/// checkpoint ([`upload_salt`]) so a resumed upload builds the same envelope.
/// An outside payer's upload without an envelope is scoped by its payer
/// (`payer`) too, so payers uploading the same file neither resume each
/// other's payments nor wait on each other's lock, which an upload holds
/// while it waits for its payment.
async fn open_upload_checkpoint(
    network: &ant_protocol::evm::Network,
    records: &[super::super::upload::UploadRecord],
    envelope: Option<&[u8]>,
    payer: Option<&[u8]>,
) -> Result<(
    PathBuf,
    std::fs::File,
    Option<super::super::upload_state::UploadState>,
)> {
    let records = records
        .iter()
        .map(|r| (r.address, r.size))
        .collect::<Vec<_>>();
    let scope = upload_checkpoint_scope(network, &records, envelope, payer)?;
    let cache_dir = crate::config::data_dir()
        .map_err(|e| Error::Config(e.to_string()))?
        .join("payments/upload");
    std::fs::create_dir_all(&cache_dir)?;
    let cache_dir = long_path_safe(cache_dir);
    let cache_path = cache_dir.join(format!(
        "{}.msgpack",
        hex::encode(blake3::hash(&scope).as_bytes())
    ));
    let lock_path = cache_path.with_extension("lock");
    let lock = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(file)
    })
    .await
    .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))??;
    let saved = match std::fs::read(&cache_path) {
        Ok(bytes) => Some(super::super::upload_state::UploadState::restore(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(Error::Io(error)),
    };
    Ok((cache_path, lock, saved))
}

/// `directory` in the form Windows takes past MAX_PATH (260 characters):
/// verbatim (`\\?\C:\...`), as `std::fs::canonicalize` gives it. The
/// checkpoints, salts and kept records under it are written through
/// tempfile's `persist`, which hands its paths to `MoveFileExW` as they are,
/// and a kept record's path ([`kept_path`]) is over 100 characters longer
/// than the directory's. Under a long data directory the rename failed: the
/// record wasn't kept and the checkpoint stayed, so a later upload of the
/// same file by the same payer resumed the finished one and returned its
/// record again, even after the caller had saved and forgotten it. The
/// checkpoints of records paid one at a time are written the same way.
/// Elsewhere, or if the directory can't be resolved, it is returned as it is.
pub(crate) fn long_path_safe(directory: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(verbatim) = std::fs::canonicalize(&directory) {
            return verbatim;
        }
    }
    directory
}

/// Where a completed upload keeps what proves its envelope until the caller
/// has saved it ([`forget_upload_record`]): under `records/` next to the
/// checkpoints, by envelope address and payer, `<address>.<payer>.record`
/// (the record's text, as [`crate::datamap_file::write_record`] writes it)
/// or, for a private envelope without a record, `<address>.<payer>.salt`.
/// `payer` is the payer's checkpoint scope ([`UploadPayer::checkpoint_scope`],
/// or the wallet's address), shortened to a hash. [`upload_salt`] never
/// reads there, so a later upload of the same file picks a new salt.
fn kept_path(upload_dir: &Path, address: &[u8; 32], payer: &[u8], extension: &str) -> PathBuf {
    let payer = blake3::hash(payer);
    upload_dir.join("records").join(format!(
        "{}.{}.{extension}",
        hex::encode(address),
        hex::encode(&payer.as_bytes()[..16])
    ))
}

/// Write `bytes` to `path`, whole or not at all.
fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing directory"))?;
    std::fs::create_dir_all(directory)?;
    // Owner-only, like the records kept next to it: tempfile creates files
    // 0600 on Unix (`salts_are_owner_only` checks it).
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Keep what proves `envelope` under `upload_dir` ([`kept_path`]): its
/// record, or the salt of a private one without a record. Nothing for a
/// readable envelope without a record: nothing of it is lost.
fn keep_upload_record(
    upload_dir: &Path,
    envelope: &UploadEnvelope,
    payer: &[u8],
) -> std::result::Result<(), String> {
    let address = envelope.address();
    match (&envelope.proof, envelope.salt) {
        (Some(proof), _) => {
            let path = kept_path(
                upload_dir,
                &address,
                payer,
                crate::datamap_file::RECORD_EXTENSION,
            );
            let directory = path.parent().ok_or("missing directory")?;
            std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
            crate::datamap_file::write_record(&path, proof).map_err(|e| e.to_string())
        }
        (None, Some(salt)) => write_whole(&kept_path(upload_dir, &address, payer, "salt"), &salt)
            .map_err(|e| e.to_string()),
        (None, None) => Ok(()),
    }
}

/// The record `payer`'s completed upload kept for `envelope`
/// ([`keep_upload_record`]), if it is still there and is for this very
/// envelope.
fn kept_upload_record(
    upload_dir: &Path,
    envelope: &UploadEnvelope,
    payer: &[u8],
) -> Option<ant_listings::EnvelopeProof> {
    let path = kept_path(
        upload_dir,
        &envelope.address(),
        payer,
        crate::datamap_file::RECORD_EXTENSION,
    );
    let record = match crate::datamap_file::read_record(&path) {
        Ok(record) => record,
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return None;
        }
        Err(e) => {
            warn!(
                "Ignoring the unreadable kept record {}: {e}",
                path.display()
            );
            return None;
        }
    };
    let ours = record.address == envelope.address()
        && record.envelope == envelope.envelope.to_bytes()
        && record.salt == envelope.salt;
    ours.then_some(record)
}

/// Finish a completed upload's checkpoint. What proves the envelope is first
/// kept by envelope address and payer ([`keep_upload_record`]), so a crash
/// before the caller has saved the record doesn't lose it; only then are the
/// salt next to the checkpoint and the checkpoint removed, in that order, so
/// a crash between the two can't leave a salt a later upload would reuse.
///
/// Never fails: the upload is paid and stored, and its result holds what the
/// caller needs, so a problem here is only logged. If the record can't be
/// kept, the checkpoint and its salt stay: the next upload of the same file
/// with the same choices by the same payer resumes, finds the envelope
/// stored, and builds the record again from the checkpoint.
fn finish_upload_checkpoint(checkpoint: &Path, envelope: Option<&UploadEnvelope>, payer: &[u8]) {
    if let Some(envelope) = envelope {
        let kept = checkpoint
            .parent()
            .ok_or_else(|| "missing checkpoint directory".to_string())
            .and_then(|directory| keep_upload_record(directory, envelope, payer));
        if let Err(e) = kept {
            warn!(
                "Could not keep the record of envelope {}, leaving the checkpoint {} \
                 to build it again: {e}",
                hex::encode(envelope.address()),
                checkpoint.display()
            );
            return;
        }
    }
    for path in [checkpoint.with_extension("salt"), checkpoint.to_path_buf()] {
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Could not remove {}: {e}", path.display());
            }
        }
    }
}

/// Delete what a completed upload kept for the envelope at `address` (its
/// record, or a private envelope's salt), once the caller has saved the
/// record (as `ant file upload` does with its `.record` file). Until then it
/// stays under the client's data directory, at
/// `payments/upload/records/<address>.<payer>.record` (or `.salt`), so a
/// crash between the upload and saving the record doesn't lose the paid
/// quote and tx hash, which nothing else may hold. Removes the copies kept
/// for every payer.
///
/// # Errors
///
/// Returns an error if the data directory can't be found or a file can't be
/// removed. Nothing kept is not an error.
pub fn forget_upload_record(address: &[u8; 32]) -> Result<()> {
    let directory = crate::config::data_dir()
        .map_err(|e| Error::Config(e.to_string()))?
        .join("payments/upload");
    forget_kept(&directory, address).map_err(Error::Io)
}

/// [`forget_upload_record`] under `upload_dir`.
fn forget_kept(upload_dir: &Path, address: &[u8; 32]) -> std::io::Result<()> {
    let prefix = format!("{}.", hex::encode(address));
    let entries = match std::fs::read_dir(upload_dir.join("records")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// The salt for a private upload's envelope: the one an interrupted attempt
/// saved next to `checkpoint`, or 32 new random bytes, saved there before
/// anything is paid. A resumed upload then builds the same envelope and
/// reuses its payment.
fn upload_salt(checkpoint: &Path) -> Result<ant_listings::Salt> {
    let path = checkpoint.with_extension("salt");
    match std::fs::read(&path) {
        Ok(bytes) => {
            if let Ok(salt) = <ant_listings::Salt>::try_from(bytes.as_slice()) {
                return Ok(salt);
            }
            warn!("Ignoring a damaged envelope salt at {}", path.display());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::Io(error)),
    }
    let salt: ant_listings::Salt = rand::random();
    write_whole(&path, &salt)?;
    Ok(salt)
}

/// How far to trust an estimate priced from a live quote. When every
/// sampled content chunk was already stored and only the chunk the upload
/// adds was quoted (`only_extra`), the price covers the content only if
/// every content chunk was sampled: otherwise the unsampled ones may still
/// need paying, as with [`CostEstimateConfidence::AllSamplesAlreadyStoredIncomplete`].
fn priced_confidence(
    only_extra: bool,
    sampled: usize,
    content_chunks: usize,
) -> CostEstimateConfidence {
    if only_extra && sampled < content_chunks {
        CostEstimateConfidence::AllSamplesAlreadyStoredIncomplete
    } else {
        CostEstimateConfidence::PricedSample
    }
}

/// The payment mode for an external-signer upload of `content_chunks`
/// chunks. One with an envelope is paid per chunk, in one wave batch, so the
/// envelope is in the same payment as the content: nodes record a listing
/// only from a per-chunk payment, and the external merkle path has no
/// per-chunk payment the envelope could join.
///
/// An envelope upload that `mode` would pay in merkle batches is refused
/// before anything is quoted or paid, rather than silently paid per chunk
/// with every chunk held in memory: the wallet and payer paths
/// ([`Client::file_upload_with_payer`]) take it, or the caller can ask for
/// [`PaymentMode::Single`].
fn external_payment_mode(
    visibility: &Visibility,
    content_chunks: usize,
    mode: PaymentMode,
) -> Result<PaymentMode> {
    if !matches!(visibility, Visibility::Envelope(_)) {
        return Ok(mode);
    }
    if should_use_merkle(content_chunks, mode) {
        return Err(Error::InvalidData(format!(
            "an upload with an envelope of {content_chunks} chunks would be paid in merkle \
             batches ({mode:?}), and the external-signer path can't pay the envelope with \
             them: upload it with a wallet or a payer (file_upload_with_payer), or ask for \
             PaymentMode::Single to pay every chunk per chunk, holding them all in memory"
        )));
    }
    Ok(PaymentMode::Single)
}

/// The chunk an upload with `visibility` stores besides its content, if
/// any, with its address: a readable upload's data map (plain, or in its
/// envelope), or a private upload's envelope, with a new random salt as the
/// upload would pick.
fn extra_upload_chunk(
    visibility: &Visibility,
    data_map: &DataMap,
) -> Result<Option<([u8; 32], Bytes)>> {
    match visibility {
        Visibility::Private => Ok(None),
        Visibility::Public => crate::client_engine::files::public_map_record(data_map)
            .map(Some)
            .map_err(Error::Serialization),
        Visibility::Envelope(options) => {
            let salt: Option<ant_listings::Salt> = (!options.readable).then(rand::random);
            let envelope = options
                .envelope(data_map, salt.as_ref())
                .map_err(|e| Error::InvalidData(format!("cannot build the envelope: {e}")))?;
            Ok(Some(crate::client_engine::files::envelope_record(
                &envelope,
            )))
        }
    }
}

/// The payment proof of the envelope's chunk among `paid_chunks`, kept to
/// build its record once the chunks are stored.
fn envelope_payment_proof(
    envelope: Option<&UploadEnvelope>,
    paid_chunks: &[PaidChunk],
) -> Option<Vec<u8>> {
    let address = envelope?.address();
    paid_chunks
        .iter()
        .find(|chunk| chunk.address == address)
        .map(|chunk| chunk.proof_bytes.clone())
}

/// Check an upload's envelope metadata before anything is paid.
fn check_envelope_options(visibility: &Visibility) -> Result<()> {
    match visibility {
        Visibility::Envelope(options) => options
            .validate()
            .map_err(|e| Error::InvalidData(format!("invalid envelope metadata: {e}"))),
        _ => Ok(()),
    }
}

/// Build an upload's envelope for `data_map`: a private one with `salt`.
fn build_upload_envelope(
    options: &EnvelopeOptions,
    data_map: &DataMap,
    salt: Option<ant_listings::Salt>,
) -> Result<(UploadEnvelope, Bytes)> {
    let envelope = options
        .envelope(data_map, salt.as_ref())
        .map_err(|e| Error::InvalidData(format!("cannot build the envelope: {e}")))?;
    let (address, bytes) = crate::client_engine::files::envelope_record(&envelope);
    info!(
        "Envelope upload: envelope chunk ({} bytes, flags {:#04x}) at address {}",
        bytes.len(),
        envelope.flags().to_byte(),
        hex::encode(address)
    );
    Ok((UploadEnvelope::new(envelope, salt), bytes))
}

/// Prepared upload ready for external payment.
///
/// Contains everything needed to construct the on-chain payment transaction
/// externally (e.g. via WalletConnect in a desktop app) and then finalize
/// the upload without a Rust-side wallet.
///
/// Note: This struct stays in Rust memory — only the public fields of
/// `payment_info` are sent to the frontend. `PreparedChunk` contains
/// non-serializable network types, so the full struct cannot derive `Serialize`.
///
/// Marked `#[non_exhaustive]` so adding a new field in future is not a
/// breaking change for downstream consumers.
#[derive(Debug)]
#[non_exhaustive]
pub struct PreparedUpload {
    /// The data map for later retrieval.
    pub data_map: DataMap,
    /// Payment information for chunks that still need payment after the
    /// already-stored preflight. This may be wave-batch even when the original
    /// chunk count was merkle-eligible if the remaining count is below the
    /// merkle threshold.
    pub payment_info: ExternalPaymentInfo,
    /// Chunk address of the serialized `DataMap` when this upload was
    /// prepared with [`Visibility::Public`]. `Some` means the address is
    /// retrievable on the network after finalization — either because this
    /// upload paid to store the chunk in `payment_info`, or because the
    /// chunk was already on the network (deterministic self-encryption).
    /// Carried through to [`FileUploadResult::data_map_address`].
    pub data_map_address: Option<[u8; 32]>,
    /// Chunk addresses already present on the network when this upload was
    /// prepared. These do not require payment or PUT during finalization.
    pub already_stored_addresses: Vec<[u8; 32]>,
    /// Total chunk count for the upload, including already-stored chunks.
    pub total_chunks: usize,
    /// The envelope of an envelope upload, stored after every other chunk.
    /// Its proof record is filled in at finalize, once every chunk is stored.
    pub envelope: Option<UploadEnvelope>,
}

/// Outcome of a resumable external-signer finalize
/// ([`Client::finalize_upload_resumable`] /
/// [`Client::finalize_upload_merkle_multi_resumable`] /
/// [`Client::finalize_resume`]).
///
/// `Complete` means every chunk is stored. `Partial` means some chunks are
/// still unstored after retries — short of quorum, or cut off by a store
/// abort; its [`FinalizeResume`] handle owns the retained payment material, so
/// the caller can store the remainder against the **same** on-chain payment
/// without re-quoting or re-signing (issue #140). Persistent store failures
/// also surface as `Partial`, so loops that retry a handle must bound their
/// attempts (see [`Client::finalize_resume`]).
#[derive(Debug)]
pub enum FinalizeOutcome {
    /// All chunks stored; the file is fully retrievable.
    Complete(FileUploadResult),
    /// Some chunks remain unstored after retries.
    Partial {
        /// Progress snapshot for this attempt (stored/failed counts, on-chain
        /// spend, `data_map_address`). Per-attempt store telemetry
        /// (`chunk_attempts_total`, `store_durations_ms`, `retries_histogram`)
        /// is not carried on a partial and reads as empty/zero.
        result: FileUploadResult,
        /// Hand back to [`Client::finalize_resume`] to store the still-unstored
        /// chunks against the same payment.
        resume: FinalizeResume,
    },
}

/// Opaque handle to resume an external-signer finalize that stored some but not
/// all chunks after retries, carrying the material needed to store the
/// remainder against the original, already-signed payment — no new quote, no
/// second signature, no double payment (issue #140).
///
/// One variant per external payment path; a caller obtains it from
/// [`FinalizeOutcome::Partial`] and passes it back to [`Client::finalize_resume`]
/// without needing to know which path produced it. Boxed variants keep the enum
/// small. Dropping it abandons the upload (the wave path frees its retained
/// chunk bodies; the merkle path removes its spill directory from disk).
#[derive(Debug)]
#[non_exhaustive]
pub enum FinalizeResume {
    /// Resume a wave-batch (single-payment) external finalize.
    Wave(Box<WaveFinalizeResume>),
    /// Resume a merkle (multi-batch) external finalize.
    Merkle(Box<MerkleFinalizeResume>),
}

/// Opaque handle to resume a wave-batch external finalize that stored some but
/// not all chunks after retries.
///
/// Owns the already-paid [`PaidChunk`]s (body + payment proof + PUT targets)
/// that still need storing; re-storing reuses those proofs, so the same
/// on-chain payment is honoured without re-signing. Dropping it frees the
/// retained chunk bodies (the upload is abandoned).
///
/// `#[non_exhaustive]` so future fields are not a breaking change. `Debug` is
/// redacted to counts only — it never prints chunk bodies, proofs, or the data
/// map.
#[non_exhaustive]
pub struct WaveFinalizeResume {
    data_map: DataMap,
    data_map_address: Option<[u8; 32]>,
    total_chunks: usize,
    stored_count: usize,
    failed_paid_chunks: Vec<PaidChunk>,
    occupied: Vec<([u8; 32], String)>,
    storage_cost_atto: String,
    envelope: Option<UploadEnvelope>,
}

impl WaveFinalizeResume {
    /// The chunks this payment can't store, each with why: the vault had
    /// recorded its paid quote for another payment first and skipped this
    /// one. They are not in the handle: every resume reports them failed and
    /// holds the envelope back, so the upload doesn't complete on this
    /// payment. Prepare it again to quote and pay them afresh.
    #[must_use]
    pub fn occupied(&self) -> &[([u8; 32], String)] {
        &self.occupied
    }
}

impl std::fmt::Debug for WaveFinalizeResume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaveFinalizeResume")
            .field("total_chunks", &self.total_chunks)
            .field("stored", &self.stored_count)
            .field("unstored", &self.failed_paid_chunks.len())
            .field("occupied", &self.occupied.len())
            .field("public", &self.data_map_address.is_some())
            .finish_non_exhaustive()
    }
}

/// Opaque handle to resume an external-signer merkle finalize that stored some
/// but not all chunks after retries.
///
/// Owns the on-disk chunk spill and the merkle proofs from the original,
/// already-signed payment, plus the addresses still to store. Passing it to
/// [`Client::finalize_resume`] re-drives storage for only those chunks — no new
/// quote, no second signature, no double payment (issue #140). Dropping it
/// removes the spill directory from disk (the upload is abandoned).
///
/// `#[non_exhaustive]` so future fields are not a breaking change. `Debug` is
/// redacted to counts only — it never prints chunk bodies, the data map, or
/// merkle proof material.
#[non_exhaustive]
pub struct MerkleFinalizeResume {
    data_map: DataMap,
    data_map_address: Option<[u8; 32]>,
    total_chunks: usize,
    chunk_store: ExternalChunkStore,
    unstored_addresses: Vec<[u8; 32]>,
    batch_result: MerkleBatchPaymentResult,
    stored_addresses: Vec<[u8; 32]>,
}

impl std::fmt::Debug for MerkleFinalizeResume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerkleFinalizeResume")
            .field("total_chunks", &self.total_chunks)
            .field("stored", &self.stored_addresses.len())
            .field("unstored", &self.unstored_addresses.len())
            .field("public", &self.data_map_address.is_some())
            .finish_non_exhaustive()
    }
}

/// Return type for [`spawn_file_encryption`]: chunk receiver, `DataMap` oneshot, join handle.
type EncryptionChannels = (
    tokio::sync::mpsc::Receiver<Bytes>,
    tokio::sync::oneshot::Receiver<DataMap>,
    tokio::task::JoinHandle<Result<()>>,
);

/// Spawn a blocking task that streams file encryption through a channel.
fn spawn_file_encryption(path: PathBuf) -> Result<EncryptionChannels> {
    let metadata = std::fs::metadata(&path)?;
    let data_size = usize::try_from(metadata.len())
        .map_err(|e| Error::Encryption(format!("file size exceeds platform usize: {e}")))?;

    let (chunk_tx, chunk_rx) = tokio::sync::mpsc::channel(2);
    let (datamap_tx, datamap_rx) = tokio::sync::oneshot::channel();

    let handle = tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)?;
        let mut reader = std::io::BufReader::new(file);

        let read_error: Arc<Mutex<Option<std::io::Error>>> = Arc::new(Mutex::new(None));
        let read_error_clone = Arc::clone(&read_error);

        let data_iter = std::iter::from_fn(move || {
            let mut buffer = vec![0u8; 8192];
            match std::io::Read::read(&mut reader, &mut buffer) {
                Ok(0) => None,
                Ok(n) => {
                    buffer.truncate(n);
                    Some(Bytes::from(buffer))
                }
                Err(e) => {
                    let mut guard = read_error_clone
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *guard = Some(e);
                    None
                }
            }
        });

        let mut stream = stream_encrypt(data_size, data_iter)
            .map_err(|e| Error::Encryption(format!("stream_encrypt failed: {e}")))?;

        for chunk_result in stream.chunks() {
            // Check for captured read errors immediately after each chunk.
            // stream_encrypt sees None (EOF) when a read fails, so it stops
            // producing chunks. We must detect this before sending the
            // partial results to avoid uploading a truncated DataMap.
            {
                let guard = read_error
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(ref e) = *guard {
                    return Err(Error::Io(std::io::Error::new(e.kind(), e.to_string())));
                }
            }

            let (_hash, content) = chunk_result
                .map_err(|e| Error::Encryption(format!("chunk encryption failed: {e}")))?;
            if chunk_tx.blocking_send(content).is_err() {
                return Err(Error::Encryption("upload receiver dropped".to_string()));
            }
        }

        // Final check: read error after last chunk (stream saw EOF).
        {
            let guard = read_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(ref e) = *guard {
                return Err(Error::Io(std::io::Error::new(e.kind(), e.to_string())));
            }
        }

        let datamap = stream
            .into_datamap()
            .ok_or_else(|| Error::Encryption("no DataMap after encryption".to_string()))?;
        if datamap_tx.send(datamap).is_err() {
            warn!("DataMap receiver dropped — upload may have been cancelled");
        }
        Ok(())
    });

    Ok((chunk_rx, datamap_rx, handle))
}

/// RAII guard for the staging temp file used during a disk download.
///
/// Removes the file on drop — including a panic unwind out of the
/// `block_in_place` decrypt loop — unless [`commit`](Self::commit) has
/// promoted it to its final path. Centralizes the cleanup the explicit error
/// arms used to repeat.
struct TempDownload {
    /// `Some` while the staging file may need cleanup; `None` once committed.
    path: Option<PathBuf>,
}

impl TempDownload {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Path of the staging file (valid until `commit`).
    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("TempDownload::path called after commit")
    }

    /// Rename the staged file to `dest`. On success the guard is defused so
    /// `Drop` is a no-op; on failure the guard stays armed and `Drop` removes
    /// the orphaned temp file.
    fn commit(mut self, dest: &Path) -> std::io::Result<()> {
        std::fs::rename(self.path(), dest)?; // err → guard armed → Drop cleans up
        self.path = None; // success → nothing left to clean
        Ok(())
    }
}

impl Drop for TempDownload {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            if let Err(e) = std::fs::remove_file(&path) {
                // Absent file is fine (never created / already gone).
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        "Failed to remove temp download file {}: {e}",
                        path.display()
                    );
                }
            }
        }
    }
}

/// Pays for an upload from outside the client, for example an agent paying
/// from its own wallet. [`Client::file_upload_with_payer`] uses it in place of
/// the client's wallet.
///
/// The upload engine saves its state before it asks for a payment. After a
/// restart it asks again, with the same plans or batch, to recover a payment
/// that may already have been made. Implementations must therefore look for an
/// earlier payment of exactly this request before asking for a new one.
// `async_trait` marks the generated methods `#[must_use]` while their boxed
// futures already are, which clippy's `double_must_use` flags (as it does on
// `UploadAdapter`).
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait UploadPayer: Send + Sync {
    /// Pay every non-zero quote in `plans` with `payForQuotes`. Returns the
    /// transaction that paid each quote hash and the total paid, which must
    /// equal the plans' total.
    async fn pay_quotes(
        &self,
        plans: &[crate::data::client::batch::ChunkPaymentPlan],
    ) -> Result<super::super::upload::UploadPayment>;

    /// Pay `batch` with one `payForMerkleTree` transaction. Returns the
    /// winning pool and the amount paid.
    async fn pay_merkle(
        &self,
        batch: &PreparedMerkleBatch,
    ) -> Result<super::super::upload::MerkleUploadPayment>;

    /// Bytes naming who pays, such as an account id or a wallet address.
    /// An upload's checkpoint, with an envelope or without, and the record a
    /// completed envelope upload keeps ([`forget_upload_record`]), belong to
    /// this payer: only the same payer resumes an interrupted upload, reusing
    /// its payment (and an envelope's salt), or gets a kept record back, and
    /// uploads of the same file by other payers don't wait for it. A payer
    /// used for several accounts must return a different value for each.
    /// Empty by default, which every payer that doesn't name itself shares.
    fn checkpoint_scope(&self) -> Vec<u8> {
        Vec::new()
    }
}

/// Where an upload's record bytes come from.
enum ChunkSource<'a> {
    /// A file's encrypted chunks, spilled to disk, with its envelope if any.
    Spill(&'a ChunkSpill),
}

impl ChunkSource<'_> {
    fn load(&self, address: &[u8; 32]) -> Result<Bytes> {
        match self {
            Self::Spill(spill) => spill.read_chunk(address),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Spill(spill) => spill.len(),
        }
    }
}

/// Uploads records from a [`ChunkSource`], paying through `payer` when there
/// is one and through the client's wallet otherwise.
struct SpillUploadAdapter<'a> {
    client: &'a Client,
    source: ChunkSource<'a>,
    progress: Option<&'a mpsc::Sender<UploadEvent>>,
    checkpoint: &'a Path,
    payer: Option<&'a dyn UploadPayer>,
}

#[async_trait::async_trait]
impl super::super::upload::UploadAdapter for SpillUploadAdapter<'_> {
    #[cfg(feature = "native")]
    fn initialize_payment_attempt(&self, attempt: &mut super::super::upload_state::PaymentAttempt) {
        if self.payer.is_none() {
            super::super::native_payment::initialize(attempt);
        }
    }
    #[cfg(feature = "native")]
    async fn submit_payment(
        &self,
        plans: &[crate::data::client::batch::ChunkPaymentPlan],
        state: &mut crate::data::client::upload_state::UploadState,
    ) -> Result<super::super::upload::UploadPayment> {
        match self.payer {
            Some(payer) => payer.pay_quotes(plans).await,
            None => super::super::native_payment::pay(self.client, self, plans, state).await,
        }
    }
    #[cfg(feature = "native")]
    async fn reconcile_payment(
        &self,
        plans: &[crate::data::client::batch::ChunkPaymentPlan],
        state: &mut crate::data::client::upload_state::UploadState,
    ) -> Result<super::super::upload::UploadPayment> {
        match self.payer {
            Some(payer) => payer.pay_quotes(plans).await,
            None => super::super::native_payment::pay(self.client, self, plans, state).await,
        }
    }
    #[cfg(feature = "native")]
    async fn submit_merkle_payment(
        &self,
        batch: &super::super::merkle::PreparedMerkleBatch,
        state: &mut crate::data::client::upload_state::UploadState,
    ) -> Result<super::super::upload::MerkleUploadPayment> {
        match self.payer {
            Some(payer) => payer.pay_merkle(batch).await,
            None => super::super::native_payment::pay_merkle(self.client, self, batch, state).await,
        }
    }
    #[cfg(feature = "native")]
    async fn reconcile_merkle_payment(
        &self,
        batch: &super::super::merkle::PreparedMerkleBatch,
        state: &mut crate::data::client::upload_state::UploadState,
    ) -> Result<super::super::upload::MerkleUploadPayment> {
        match self.payer {
            Some(payer) => payer.pay_merkle(batch).await,
            None => super::super::native_payment::pay_merkle(self.client, self, batch, state).await,
        }
    }
    async fn load(&self, record: super::super::upload::UploadRecord) -> Result<Bytes> {
        self.source.load(&record.address)
    }
    async fn pay(
        &self,
        plans: &[crate::data::client::batch::ChunkPaymentPlan],
    ) -> Result<super::super::upload::UploadPayment> {
        if let Some(payer) = self.payer {
            return payer.pay_quotes(plans).await;
        }
        let adapter = super::super::upload::MemoryUploadAdapter {
            client: self.client,
            chunks: &[],
            progress: self.progress,
            stored_offset: 0,
            file_total: self.source.len(),
            resume_key: None,
        };
        adapter.pay(plans).await
    }
    async fn pay_merkle(
        &self,
        batch: &PreparedMerkleBatch,
    ) -> Result<super::super::upload::MerkleUploadPayment> {
        if let Some(payer) = self.payer {
            return payer.pay_merkle(batch).await;
        }
        let adapter = super::super::upload::MemoryUploadAdapter {
            client: self.client,
            chunks: &[],
            progress: self.progress,
            stored_offset: 0,
            file_total: self.source.len(),
            resume_key: None,
        };
        adapter.pay_merkle(batch).await
    }
    async fn checkpoint(
        &self,
        state: &super::super::upload_state::UploadState,
        _: Option<&super::super::upload::UploadPayment>,
    ) -> Result<()> {
        use std::io::Write;
        let bytes = state.checkpoint()?;
        let directory = self
            .checkpoint
            .parent()
            .ok_or_else(|| Error::Config("missing checkpoint directory".into()))?;
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(self.checkpoint)
            .map_err(|e| Error::Io(e.error))?;
        Ok(())
    }
    fn stored(&self, stored: usize, total: usize) {
        if let Some(progress) = self.progress {
            let _ = progress.try_send(UploadEvent::ChunkStored { stored, total });
        }
    }
    fn quoted(&self, quoted: usize, total: usize) {
        if let Some(progress) = self.progress {
            let _ = progress.try_send(UploadEvent::ChunkQuoted { quoted, total });
        }
    }
}

impl Client {
    /// Upload a file to the network using streaming self-encryption, in a
    /// private envelope that shows every payment field, as `darwin file
    /// upload` stores it by default ([`Visibility::default`]).
    ///
    /// The envelope, its salt and the record proving its payment are in
    /// [`FileUploadResult::envelope`]; the record is also kept under the
    /// data directory until the caller has saved it and calls
    /// [`forget_upload_record`]. Use
    /// [`Client::file_upload_with_visibility_and_progress`] for other
    /// choices.
    ///
    /// Pays per chunk ([`PaymentMode::Single`], the default; see
    /// [`PaymentMode`] for why not in merkle batches). Encrypted chunks are
    /// spilled to a temp directory so peak memory stays at ~256 MB regardless
    /// of file size.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, encryption fails,
    /// or any chunk cannot be stored.
    pub async fn file_upload(&self, path: &Path) -> Result<FileUploadResult> {
        self.file_upload_with_mode(path, PaymentMode::default())
            .await
    }

    /// Estimate the cost of uploading a file without actually uploading, in
    /// the private envelope [`Client::file_upload`] stores.
    ///
    /// Encrypts the file to determine chunk count and sizes, then requests
    /// a single quote from the network for a representative chunk. The
    /// per-chunk price is extrapolated to the total chunk count.
    ///
    /// The estimate is fast (~2-5s) and does not require a wallet. Spilled
    /// chunks are cleaned up automatically when the function returns.
    ///
    /// Gas cost is an advisory heuristic, not a live gas-oracle query. It is
    /// derived from realistic per-transaction budgets (`GAS_PER_WAVE_TX`,
    /// `GAS_PER_MERKLE_TX`) priced at `ARBITRUM_GAS_PRICE_WEI`. Real gas
    /// varies with network conditions.
    ///
    /// Sampled chunk addresses are spread across the whole file (not the first
    /// N) so a shared leading prefix doesn't bias the sample. When a sample
    /// returns a live quote the per-chunk price is extrapolated and the result
    /// is tagged [`CostEstimateConfidence::PricedSample`].
    ///
    /// When every sampled chunk is already stored the result is still `Ok`
    /// with `storage_cost_atto: "0"`, tagged either
    /// [`CostEstimateConfidence::VerifiedAllAlreadyStored`] when the whole file
    /// was sampled (exactly free) or
    /// [`CostEstimateConfidence::AllSamplesAlreadyStoredIncomplete`] when the
    /// tail was unsampled (a best-effort guess that payment reconciles).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, encryption fails, or the
    /// network cannot provide a quote.
    pub async fn estimate_upload_cost(
        &self,
        path: &Path,
        mode: PaymentMode,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<UploadCostEstimate> {
        self.estimate_upload_cost_with_visibility(
            path,
            mode,
            super::super::envelope::private_shortcut_visibility(),
            progress,
        )
        .await
    }

    /// Estimate the cost of uploading a file with `visibility`, as
    /// [`Client::estimate_upload_cost`] does for a private envelope.
    ///
    /// A readable upload stores one more chunk, its data map (plain, or in
    /// its envelope), and so does a private upload with an envelope. That
    /// chunk is counted in `chunk_count` and priced like the others: a public
    /// data map goes with the content, an envelope is always paid per chunk.
    /// When the sampled content is already stored, the extra chunk is quoted
    /// on its own (a private envelope never is stored: its salt is new): a
    /// [`CostEstimateConfidence::PricedSample`] if every content chunk was
    /// sampled, else [`CostEstimateConfidence::AllSamplesAlreadyStoredIncomplete`]
    /// with the extra chunk's price, since the unsampled content may still
    /// need paying.
    ///
    /// # Errors
    ///
    /// As [`Client::estimate_upload_cost`].
    pub async fn estimate_upload_cost_with_visibility(
        &self,
        path: &Path,
        mode: PaymentMode,
        visibility: Visibility,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<UploadCostEstimate> {
        let visibility = visibility.normalized();
        check_envelope_options(&visibility)?;
        let file_size = std::fs::metadata(path).map_err(Error::Io)?.len();

        if file_size < 3 {
            return Err(Error::InvalidData(
                "File too small: self-encryption requires at least 3 bytes".into(),
            ));
        }

        check_disk_space_for_spill(file_size)?;

        info!(
            "Estimating upload cost for {} ({file_size} bytes)",
            path.display()
        );

        let (spill, data_map) = self.encrypt_file_to_spill(path, progress.as_ref()).await?;
        let content_chunks = spill.len();
        // The chunk the upload adds to its content, and how it is paid: an
        // envelope is kept out of merkle batches, a public data map is not.
        let extra = extra_upload_chunk(&visibility, &data_map)?;
        let chunk_count = content_chunks + usize::from(extra.is_some());
        let envelope_per_chunk = matches!(visibility, Visibility::Envelope(_));
        let batched = if envelope_per_chunk {
            content_chunks
        } else {
            chunk_count
        };

        if let Some(ref tx) = progress {
            let _ = tx
                .send(UploadEvent::Encrypted {
                    total_chunks: chunk_count,
                })
                .await;
        }

        info!("Encrypted into {chunk_count} chunks, requesting quote");
        let uses_merkle = should_use_merkle(batched, mode);

        // Sample chunk addresses spread evenly across the file (see
        // `distributed_sample_indices`) rather than the first N. A single
        // AlreadyStored result says nothing about the rest of the file, and a
        // positional sample lands on a shared leading prefix in the worst case,
        // so we spread the probe and only treat the whole file as "fully
        // stored" when every sample comes back stored.
        let sample_indices = distributed_sample_indices(spill.addresses.len(), ESTIMATE_SAMPLE_CAP);
        let mut sampled = 0usize;
        let mut all_already_stored = true;
        let mut quotes_opt: Option<Vec<QuoteEntry>> = None;

        for &idx in &sample_indices {
            let addr = &spill.addresses[idx];
            sampled += 1;
            let chunk_bytes = spill.read_chunk(addr)?;
            let data_size = u64::try_from(chunk_bytes.len())
                .map_err(|e| Error::InvalidData(format!("chunk size too large: {e}")))?;
            let result = if uses_merkle {
                self.get_store_quotes_with_fault_tolerance(addr, data_size, DATA_TYPE_CHUNK)
                    .await
            } else {
                self.get_store_quotes(addr, data_size, DATA_TYPE_CHUNK)
                    .await
            };
            match result {
                Ok(q) => {
                    quotes_opt = Some(q);
                    all_already_stored = false;
                    break;
                }
                Err(Error::AlreadyStored) => {
                    debug!(
                        "Sample chunk {} already stored; trying next address ({sampled}/{})",
                        hex::encode(addr),
                        sample_indices.len()
                    );
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        // The content looks stored: the extra chunk may still need paying.
        let mut only_extra = false;
        if let (None, Some((address, bytes))) = (&quotes_opt, &extra) {
            let data_size = u64::try_from(bytes.len())
                .map_err(|e| Error::InvalidData(format!("chunk size too large: {e}")))?;
            match self
                .get_store_quotes(address, data_size, DATA_TYPE_CHUNK)
                .await
            {
                Ok(q) => {
                    quotes_opt = Some(q);
                    only_extra = true;
                }
                Err(Error::AlreadyStored) => {}
                Err(e) => return Err(e),
            }
        }

        let quotes = match quotes_opt {
            Some(q) => q,
            None if all_already_stored && sampled == content_chunks => {
                // Every address in the file was sampled and every one is
                // already on the network — a zero-cost estimate is exact here.
                info!("All {chunk_count} chunks already stored; returning zero-cost estimate");
                return Ok(UploadCostEstimate {
                    file_size,
                    chunk_count,
                    storage_cost_atto: "0".into(),
                    estimated_gas_cost_wei: "0".into(),
                    payment_mode: if uses_merkle {
                        PaymentMode::Merkle
                    } else {
                        PaymentMode::Single
                    },
                    confidence: CostEstimateConfidence::VerifiedAllAlreadyStored,
                });
            }
            None => {
                // Every sampled chunk was already stored but the tail was not
                // sampled, so there is no live price to extrapolate. The
                // estimate is display-only and payment reconciles the true
                // cost, so return an optimistic zero flagged as incomplete
                // rather than erroring — callers still get a value to show.
                info!(
                    "All {sampled}/{chunk_count} sampled chunks already stored; \
                     returning incomplete zero-cost estimate"
                );
                return Ok(UploadCostEstimate {
                    file_size,
                    chunk_count,
                    storage_cost_atto: "0".into(),
                    estimated_gas_cost_wei: "0".into(),
                    payment_mode: if uses_merkle {
                        PaymentMode::Merkle
                    } else {
                        PaymentMode::Single
                    },
                    confidence: CostEstimateConfidence::AllSamplesAlreadyStoredIncomplete,
                });
            }
        };

        // Use the median price × 3, matching the settlement multiplier both
        // payment paths now apply.
        let prices: Vec<Amount> = quotes.iter().map(|(_, _, _, price, _)| *price).collect();
        let median_price = crate::payment_policy::median_quote_index(&prices)
            .map_or(Amount::ZERO, |index| prices[index]);
        let per_chunk_cost = crate::payment_policy::enhanced_payment_amount(median_price)
            .map_err(|error| Error::Payment(error.to_string()))?;

        let chunk_count_u64 = u64::try_from(chunk_count).unwrap_or(u64::MAX);
        let batched_u64 = u64::try_from(batched).unwrap_or(u64::MAX);
        // Merkle settles per *padded* leaf, not per chunk: the contract charges
        // `median16 × 2^depth` per batch and the tree rounds up to a power of
        // two, so a 65-chunk batch pays for 128 leaves. The total is summed
        // over the batches the upload engine really builds, plus the remainder
        // it pays per chunk (`merkle_upload_split`), so the estimate cannot
        // drift from execution. An envelope is paid per chunk on top.
        let merkle_split = merkle_upload_split(batched, batched);
        let billable_units = if only_extra {
            1
        } else if uses_merkle {
            merkle_upload_billable_units(batched_u64).saturating_add(u64::from(envelope_per_chunk))
        } else {
            chunk_count_u64
        };
        let total_storage = per_chunk_cost * Amount::from(billable_units);

        // Estimate gas cost from realistic per-transaction budgets rather
        // than a flat per-chunk or per-wave number.
        //
        // - Single mode: a wave's payment packs up to UPLOAD_WAVE_SIZE chunks'
        //   close-group quotes into one `pay_for_quotes` call on Arbitrum.
        //   The dominant cost is one SSTORE per entry plus base tx overhead,
        //   so we use GAS_PER_WAVE_TX (≈1.5M) as a conservative upper bound
        //   on a full wave and multiply by the number of waves. The previous
        //   per-wave figure of 150k was closer to a single-entry transfer
        //   and understated cost by 5–10x for full waves.
        // - Merkle mode: one tx per sub-batch that verifies a merkle tree
        //   and posts a pool commitment (GAS_PER_MERKLE_TX ≈ 500k each),
        //   plus one wave tx when a remainder is paid per chunk.
        //
        // Gas is priced at ARBITRUM_GAS_PRICE_WEI (~0.1 gwei, a typical
        // Arbitrum baseline). Treat the result as advisory, not a commitment.
        let waves = u128::try_from(chunk_count.div_ceil(UPLOAD_WAVE_SIZE)).unwrap_or(u128::MAX);
        // One tx per batch the upload engine builds — same split the unit
        // total above is derived from.
        let merkle_batches = u128::try_from(merkle_split.batches.len()).unwrap_or(u128::MAX);
        let remainder_waves = u128::from(merkle_split.per_chunk > 0 || envelope_per_chunk);
        let estimated_gas: u128 = if only_extra {
            GAS_PER_WAVE_TX.saturating_mul(ARBITRUM_GAS_PRICE_WEI)
        } else if uses_merkle {
            merkle_batches
                .saturating_mul(GAS_PER_MERKLE_TX)
                .saturating_add(remainder_waves.saturating_mul(GAS_PER_WAVE_TX))
                .saturating_mul(ARBITRUM_GAS_PRICE_WEI)
        } else {
            waves
                .saturating_mul(GAS_PER_WAVE_TX)
                .saturating_mul(ARBITRUM_GAS_PRICE_WEI)
        };

        info!(
            "Estimate: {chunk_count} chunks, storage={total_storage} atto, gas~={estimated_gas} wei"
        );

        Ok(UploadCostEstimate {
            file_size,
            chunk_count,
            storage_cost_atto: total_storage.to_string(),
            estimated_gas_cost_wei: estimated_gas.to_string(),
            payment_mode: if uses_merkle && !only_extra {
                PaymentMode::Merkle
            } else {
                PaymentMode::Single
            },
            confidence: priced_confidence(only_extra, sampled, content_chunks),
        })
    }

    /// Phase 1 of external-signer upload: encrypt file and prepare chunks.
    ///
    /// Equivalent to [`Client::file_prepare_upload_with_visibility`] with a
    /// private envelope that shows every payment field
    /// ([`Visibility::default`], as [`Client::file_upload`] stores) — see
    /// that method for details.
    pub async fn file_prepare_upload(&self, path: &Path) -> Result<PreparedUpload> {
        self.file_prepare_upload_with_progress(
            path,
            super::super::envelope::private_shortcut_visibility(),
            None,
        )
        .await
    }

    /// Phase 1 of external-signer upload with explicit [`Visibility`] control.
    ///
    /// Equivalent to [`Client::file_prepare_upload_with_progress`] with
    /// `progress: None` — see that method for details.
    pub async fn file_prepare_upload_with_visibility(
        &self,
        path: &Path,
        visibility: Visibility,
    ) -> Result<PreparedUpload> {
        self.file_prepare_upload_with_progress(path, visibility, None)
            .await
    }

    /// Phase 1 of external-signer upload with progress events.
    ///
    /// Equivalent to [`Client::file_prepare_upload_with_mode`] with the
    /// default [`PaymentMode::Single`] — see that method for details.
    pub async fn file_prepare_upload_with_progress(
        &self,
        path: &Path,
        visibility: Visibility,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<PreparedUpload> {
        self.file_prepare_upload_with_mode(path, visibility, PaymentMode::default(), progress)
            .await
    }

    /// Phase 1 of external-signer upload with an explicit [`PaymentMode`].
    ///
    /// Requires an EVM network (for contract price queries) but NOT a wallet.
    /// Returns a [`PreparedUpload`] containing the data map and either a
    /// [`PaymentIntent`] (wave-batch) or prepared merkle sub-batches that
    /// the external signer uses to construct and submit the on-chain payment
    /// transaction(s) — one per sub-batch (ADR-0003).
    ///
    /// `mode` mirrors the wallet path's [`Client::file_upload_with_mode`]:
    /// [`PaymentMode::Auto`] picks merkle at the chunk threshold,
    /// [`PaymentMode::Merkle`] forces merkle for ≥ 2 upload chunks (this is
    /// how tests exercise the external merkle flow with small files), and
    /// [`PaymentMode::Single`] forces wave-batch.
    ///
    /// When `visibility` is [`Visibility::Public`], the serialized `DataMap`
    /// is bundled into the payment batch as an additional chunk and its
    /// address is recorded on the returned [`PreparedUpload`]. After
    /// [`Client::finalize_upload`] (or `_merkle`) succeeds, that address is
    /// surfaced via [`FileUploadResult::data_map_address`] so the uploader
    /// can share a single address from which anyone can retrieve the file.
    ///
    /// When `visibility` is [`Visibility::Envelope`], the envelope is bundled
    /// the same way ([`PreparedUpload::envelope`]), and the upload is paid
    /// per chunk in one wave batch, so the envelope is in the same payment as
    /// the content. Its payment intent lists the payments in quote-hash
    /// order: pay them in that order, so the envelope's vault log isn't
    /// always the last of the transaction, which would give away its log
    /// index. An envelope upload `mode` would pay in merkle batches
    /// ([`PaymentMode::Auto`] from 64 chunks, [`PaymentMode::Merkle`]) is
    /// refused with [`Error::InvalidData`] before anything is quoted: use
    /// [`Client::file_upload_with_payer`], or [`PaymentMode::Single`] to pay
    /// it per chunk with every chunk held in memory. Finalize stores the
    /// envelope after every other chunk and then fills in its proof record.
    /// No EVM network is needed: without one the record is built unchecked,
    /// and the prepared envelope's `proof_problem` says so before payment.
    ///
    /// When `progress` is `Some`, [`UploadEvent`]s are emitted on the channel
    /// during encryption ([`UploadEvent::Encrypting`] / [`UploadEvent::Encrypted`])
    /// and per-chunk quoting ([`UploadEvent::ChunkQuoted`]). Storage events are
    /// emitted later by [`Client::finalize_upload_with_progress`] /
    /// [`Client::finalize_upload_merkle_with_progress`].
    ///
    /// **Memory note:** on the merkle path, chunk bodies stay in the on-disk
    /// encryption spill inside the returned [`PreparedUpload`] and are read
    /// back ≤ store-cap at a time during finalize, so peak RAM stays bounded
    /// (~256 MB) regardless of file size (ADR-0003). The spill directory
    /// lives as long as the `PreparedUpload` does. The wave-batch path —
    /// below the merkle threshold, so < ~64 × 4 MiB of chunks (unless
    /// [`PaymentMode::Single`] forces it for a larger file) — still holds
    /// its chunk bodies resident.
    ///
    /// # Errors
    ///
    /// Returns an error if there is insufficient disk space, the file cannot
    /// be read, encryption fails, or quote collection fails.
    pub async fn file_prepare_upload_with_mode(
        &self,
        path: &Path,
        visibility: Visibility,
        mode: PaymentMode,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<PreparedUpload> {
        let visibility = visibility.normalized();
        check_envelope_options(&visibility)?;
        debug!(
            "Preparing file upload for external signing (visibility={visibility:?}, mode={mode:?}): {}",
            path.display()
        );

        let file_size = std::fs::metadata(path)?.len();
        check_disk_space_for_spill(file_size)?;

        let (mut spill, data_map) = self.encrypt_file_to_spill(path, progress.as_ref()).await?;

        info!(
            "Encrypted {} into {} chunks for external signing (spilled to disk)",
            path.display(),
            spill.len()
        );
        let mode = external_payment_mode(&visibility, spill.len(), mode)?;

        // For public uploads, bundle the serialized DataMap as an extra chunk
        // in the same payment batch. This lets the external signer pay for
        // the data chunks and the DataMap chunk in one flow, and lets the
        // finalize step return the DataMap's chunk address as the shareable
        // retrieval address. It joins the spill like any data chunk so the
        // merkle path stays disk-backed; `push` dedups by address.
        let mut envelope = None;
        let data_map_address = match visibility {
            Visibility::Private => None,
            Visibility::Public => {
                let (address, serialized) =
                    crate::client_engine::files::public_map_record(&data_map)
                        .map_err(Error::Serialization)?;
                info!(
                    "Public upload: bundling DataMap chunk ({} bytes) at address {}",
                    serialized.len(),
                    hex::encode(address)
                );
                spill.push(&serialized)?;
                Some(address)
            }
            Visibility::Envelope(ref options) => {
                let salt = (!options.readable).then(rand::random);
                let (mut prepared, serialized) = build_upload_envelope(options, &data_map, salt)?;
                self.note_unchecked_envelope(&mut prepared);
                spill.push(&serialized)?;
                let address = prepared.address();
                envelope = Some(prepared);
                options.readable.then_some(address)
            }
        };

        let chunk_count = spill.len();

        if let Some(ref tx) = progress {
            let _ = tx
                .send(UploadEvent::Encrypted {
                    total_chunks: chunk_count,
                })
                .await;
        }

        let (mut payment_info, already_stored_addresses) = if should_use_merkle(chunk_count, mode) {
            // Merkle path: build tree(s), collect candidate pools, return for
            // external payment. Chunk bodies stay in the spill on disk.
            info!("Using merkle batch preparation for {chunk_count} file chunks");

            let chunk_entries = spill.chunk_entries()?;

            let merkle_plan = self
                .plan_merkle_upload(chunk_entries, DATA_TYPE_CHUNK, progress.as_ref())
                .await?;

            if merkle_plan.to_upload.is_empty() {
                info!("All {chunk_count} file chunks already stored; no external payment needed");
                (
                    ExternalPaymentInfo::WaveBatch {
                        prepared_chunks: Vec::new(),
                        payment_intent: PaymentIntent::from_prepared_chunks(&[]),
                    },
                    merkle_plan.already_stored,
                )
            } else if !should_use_merkle(merkle_plan.to_upload.len(), mode) {
                info!(
                    "{} file chunks need upload after merkle preflight; preparing wave-batch payment",
                    merkle_plan.to_upload.len()
                );
                let chunk_data = spill.read_chunks(&merkle_plan.to_upload)?;
                let (payment_info, mut wave_already_stored) = self
                    .prepare_wave_batch_external_chunks(chunk_data, progress.as_ref(), chunk_count)
                    .await?;
                let mut already_stored = merkle_plan.already_stored;
                already_stored.append(&mut wave_already_stored);
                (payment_info, already_stored)
            } else {
                // One signature pays one tree, so the to-upload set is
                // partitioned into `MerkleTree`-sized sub-batches and the
                // signer pays each — the external equivalent of the wallet
                // path's multi-transaction split (ADR-0003).
                match self
                    .prepare_merkle_batches_external(
                        &merkle_plan.to_upload,
                        DATA_TYPE_CHUNK,
                        merkle_plan.to_upload_avg_size(),
                        self.merkle_external_batch_cap(),
                    )
                    .await
                {
                    Ok(prepared_batches) => {
                        info!(
                            "File prepared for external merkle signing: {} chunks in {} sub-batch(es) ({})",
                            merkle_plan.to_upload.len(),
                            prepared_batches.len(),
                            path.display()
                        );

                        (
                            ExternalPaymentInfo::Merkle {
                                prepared_batches,
                                chunk_store: ExternalChunkStore::from_spill(spill),
                                chunk_addresses: merkle_plan.to_upload,
                            },
                            merkle_plan.already_stored,
                        )
                    }
                    Err(
                        Error::InsufficientPeers(ref msg) | Error::BatchPaymentsRefused(ref msg),
                    ) => {
                        info!(
                            "External merkle preparation found no batch to pay ({msg}); preparing wave-batch payment"
                        );
                        let chunk_data = spill.read_chunks(&merkle_plan.to_upload)?;
                        let (payment_info, mut wave_already_stored) = self
                            .prepare_wave_batch_external_chunks(
                                chunk_data,
                                progress.as_ref(),
                                chunk_count,
                            )
                            .await?;
                        let mut already_stored = merkle_plan.already_stored;
                        already_stored.append(&mut wave_already_stored);
                        (payment_info, already_stored)
                    }
                    Err(e) => return Err(e),
                }
            }
        } else {
            // Wave path: below the merkle threshold (or PaymentMode::Single),
            // chunk bodies come back resident for per-chunk quoting.
            let chunk_data = spill.read_all_chunks()?;
            self.prepare_wave_batch_external_chunks(chunk_data, progress.as_ref(), chunk_count)
                .await?
        };

        if envelope.is_some() {
            // The envelope's log must not be the last of its payment.
            if let ExternalPaymentInfo::WaveBatch { payment_intent, .. } = &mut payment_info {
                payment_intent.sort_by_quote_hash();
            }
        }

        // Surface the "DataMap chunk was already on the network" case
        // so debugging "why is data_map_address set but no storage cost
        // appears for it?" doesn't require reading the source. See the
        // `data_map_address` doc comment for why this is still a valid
        // `Some(addr)` outcome.
        if let Some(addr) = data_map_address {
            let data_map_needs_payment = match &payment_info {
                ExternalPaymentInfo::WaveBatch {
                    prepared_chunks, ..
                } => prepared_chunks.iter().any(|c| c.address == addr),
                ExternalPaymentInfo::Merkle {
                    chunk_addresses, ..
                } => chunk_addresses.contains(&addr),
            };
            if !data_map_needs_payment {
                info!(
                    "Public upload: DataMap chunk {} was already stored \
                     on the network — address is retrievable without a \
                     new payment",
                    hex::encode(addr)
                );
            }
        }

        Ok(PreparedUpload {
            data_map,
            payment_info,
            data_map_address,
            already_stored_addresses,
            total_chunks: chunk_count,
            envelope,
        })
    }

    async fn prepare_wave_batch_external_chunks(
        &self,
        chunk_data: Vec<Bytes>,
        progress: Option<&mpsc::Sender<UploadEvent>>,
        progress_total: usize,
    ) -> Result<(ExternalPaymentInfo, Vec<[u8; 32]>)> {
        let chunk_count = chunk_data.len();
        let chunks_with_addr: Vec<(Bytes, [u8; 32])> = chunk_data
            .into_iter()
            .map(|content| {
                let address = compute_address(&content);
                (content, address)
            })
            .collect();

        // Wave-batch path: collect quotes per chunk concurrently, emitting
        // a `ChunkQuoted` event after each completion so callers can drive
        // a progress bar through the slow quote phase.
        let quote_limiter = self.controller().quote.clone();
        let quote_concurrency = quote_limiter.current().min(chunk_count.max(1));
        let mut quote_stream = crate::client_engine::bounded_unordered(
            chunks_with_addr.into_iter().map(|(content, address)| {
                let limiter = quote_limiter.clone();
                async move {
                    let result = observe_op(
                        &limiter,
                        || async move { self.prepare_chunk_payment(content).await },
                        classify_error,
                    )
                    .await;
                    (address, result)
                }
            }),
            quote_concurrency,
        );

        let mut prepared_chunks = Vec::with_capacity(chunk_count);
        let mut already_stored = Vec::new();
        let mut quoted = 0usize;
        while let Some((address, result)) = quote_stream.next().await {
            match result? {
                Some(prepared) => prepared_chunks.push(prepared),
                None => already_stored.push(address),
            }
            quoted += 1;
            if let Some(tx) = progress {
                let _ = tx.try_send(UploadEvent::ChunkQuoted {
                    quoted,
                    total: progress_total,
                });
            }
        }

        let payment_intent = PaymentIntent::from_prepared_chunks(&prepared_chunks);
        info!(
            "Prepared external wave-batch payment: {} chunks, {} already stored, total {} atto",
            prepared_chunks.len(),
            already_stored.len(),
            payment_intent.total_amount,
        );

        Ok((
            ExternalPaymentInfo::WaveBatch {
                prepared_chunks,
                payment_intent,
            },
            already_stored,
        ))
    }

    /// Phase 2 of external-signer upload (wave-batch): finalize with externally-signed tx hashes.
    ///
    /// Takes a [`PreparedUpload`] that used wave-batch payment and a map
    /// of `quote_hash -> tx_hash` provided by the external signer after on-chain
    /// payment. Builds payment proofs and stores chunks on the network.
    ///
    /// Every paid quote's vault record is read back first, through the
    /// client's EVM network ([`Client::with_wallet`] or
    /// [`Client::with_evm_network`]; a client with neither reads nothing back
    /// and logs a warning). A chunk whose
    /// quote the vault had already recorded for another payment was not paid
    /// (the vault skipped the payment, which moved no tokens), so it is not
    /// sent: it fails with an error starting
    /// [`QUOTES_OCCUPIED`](crate::data::QUOTES_OCCUPIED) naming the node that
    /// issued the quote, the envelope is held back, the cost reported leaves
    /// the skipped payment out, and the upload has to be prepared again for
    /// that chunk, since a finalize can't quote it again.
    ///
    /// # Errors
    ///
    /// Returns an error if the prepared upload used merkle payment (use
    /// [`Client::finalize_upload_merkle`] instead), proof construction fails,
    /// or any chunk cannot be stored, an occupied one included
    /// ([`Error::PartialUpload`]).
    pub async fn finalize_upload(
        &self,
        prepared: PreparedUpload,
        tx_hash_map: &HashMap<QuoteHash, TxHash>,
    ) -> Result<FileUploadResult> {
        self.finalize_upload_with_progress(prepared, tx_hash_map, None)
            .await
    }

    /// Phase 2 of external-signer upload (wave-batch) with progress events.
    ///
    /// Same as [`Client::finalize_upload`] but emits [`UploadEvent::ChunkStored`]
    /// on the provided channel as each chunk is successfully stored.
    ///
    /// # Errors
    ///
    /// Same as [`Client::finalize_upload`].
    pub async fn finalize_upload_with_progress(
        &self,
        prepared: PreparedUpload,
        tx_hash_map: &HashMap<QuoteHash, TxHash>,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FileUploadResult> {
        let data_map_address = prepared.data_map_address;
        let already_stored_addresses = prepared.already_stored_addresses;
        let already_stored_count = already_stored_addresses.len();
        let total_chunks = prepared.total_chunks;
        let mut envelope = prepared.envelope;
        match prepared.payment_info {
            ExternalPaymentInfo::WaveBatch {
                prepared_chunks,
                payment_intent,
            } => {
                let plans = plans_of(&prepared_chunks);
                let paid_chunks = finalize_batch_payment(prepared_chunks, tx_hash_map)?;
                let read_back = self
                    .read_back_outside_payment(&plans, paid_chunks, payment_intent.total_amount)
                    .await;
                let envelope_proof = envelope_payment_proof(envelope.as_ref(), &read_back.paid);
                let wave_result = self
                    .store_paid_chunks_then(
                        read_back.paid,
                        envelope.as_ref().map(UploadEnvelope::address),
                        read_back.unpaid,
                        progress.as_ref(),
                        already_stored_count,
                        total_chunks,
                    )
                    .await;
                if !wave_result.failed.is_empty() {
                    let failed_count = wave_result.failed.len();
                    let stored_count = already_stored_count + wave_result.stored.len();
                    let mut stored = already_stored_addresses;
                    stored.extend(wave_result.stored);
                    return Err(Error::PartialUpload {
                        stored,
                        stored_count,
                        failed: wave_result.failed,
                        failed_count,
                        total_chunks,
                        // Report the storage spend known from the payment intent
                        // the external signer was handed, less the payments the
                        // vault skipped. Gas is paid by the signer out-of-band,
                        // so it stays unknown (0).
                        spend: Box::new(PartialUploadSpend {
                            storage_cost_atto: read_back.storage_cost_atto,
                            gas_cost_wei: 0,
                        }),
                        reason: read_back.reason.map_or_else(
                            || "finalize_upload: chunk storage failed after retries".into(),
                            |occupied| format!("finalize_upload: {occupied}"),
                        ),
                    });
                }
                let chunks_stored = already_stored_count + wave_result.stored.len();

                info!("External-signer upload finalized: {chunks_stored} chunks stored");
                // Built after the store, so reading the chain never stands
                // between a paid upload and storing it.
                if let Some(envelope) = envelope.as_mut() {
                    self.complete_external_envelope(
                        envelope,
                        &prepared.data_map,
                        envelope_proof.as_deref(),
                    )
                    .await;
                }

                let mut stats = WaveAggregateStats::default();
                stats.absorb(&wave_result);

                Ok(FileUploadResult {
                    data_map: prepared.data_map,
                    chunks_stored,
                    chunks_failed: 0,
                    total_chunks,
                    payment_mode_used: PaymentMode::Single,
                    // Storage spend is known from the payment intent; gas is
                    // paid by the external signer out-of-band (unknown here).
                    storage_cost_atto: read_back.storage_cost_atto,
                    gas_cost_wei: 0,
                    data_map_address,
                    chunk_attempts_total: stats.chunk_attempts_total,
                    store_durations_ms: stats.store_durations_ms,
                    retries_histogram: stats.retries_histogram,
                    envelope,
                })
            }
            ExternalPaymentInfo::Merkle { .. } => Err(Error::Payment(
                "Cannot finalize merkle upload with wave-batch tx hashes. \
                 Use finalize_upload_merkle() instead."
                    .to_string(),
            )),
        }
    }

    /// Per-batch leaf cap for external merkle preparation: the configured
    /// test override clamped to `3..=MAX_LEAVES` (see
    /// [`merkle_batch_sizes_with_cap`] for why 3 is the floor), or
    /// `MAX_LEAVES` (ADR-0003).
    fn merkle_external_batch_cap(&self) -> usize {
        self.config()
            .merkle_external_batch_cap
            .map_or(MAX_LEAVES, |cap| cap.clamp(3, MAX_LEAVES))
    }

    /// Phase 2 of external-signer upload (merkle): finalize with winner pool hash.
    ///
    /// The single-batch special case of
    /// [`Client::finalize_upload_merkle_multi`]: valid only for uploads that
    /// prepared as exactly one merkle sub-batch (any fresh upload below
    /// `MAX_LEAVES` chunks). Generates proofs and stores chunks on the
    /// network.
    ///
    /// # Errors
    ///
    /// Returns an error if the prepared upload used wave-batch payment (use
    /// [`Client::finalize_upload`] instead), was prepared as more than one
    /// sub-batch (use [`Client::finalize_upload_merkle_multi`]), or proof
    /// generation fails. Chunks still short of quorum after all retries
    /// surface as [`Error::PartialUpload`] carrying the stored and failed
    /// addresses — the same contract as [`Client::finalize_upload`].
    /// Re-preparing the same file skips chunks that are already stored.
    pub async fn finalize_upload_merkle(
        &self,
        prepared: PreparedUpload,
        winner_pool_hash: [u8; 32],
    ) -> Result<FileUploadResult> {
        self.finalize_upload_merkle_with_progress(prepared, winner_pool_hash, None)
            .await
    }

    /// Phase 2 of external-signer upload (merkle) with progress events.
    ///
    /// Same as [`Client::finalize_upload_merkle`] but emits [`UploadEvent::ChunkStored`]
    /// on the provided channel as each chunk is successfully stored.
    ///
    /// # Errors
    ///
    /// Same as [`Client::finalize_upload_merkle`].
    pub async fn finalize_upload_merkle_with_progress(
        &self,
        prepared: PreparedUpload,
        winner_pool_hash: [u8; 32],
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FileUploadResult> {
        if let ExternalPaymentInfo::Merkle {
            prepared_batches, ..
        } = &prepared.payment_info
        {
            let batches = prepared_batches.len();
            if batches != 1 {
                return Err(Error::Payment(format!(
                    "This upload was prepared as {batches} merkle sub-batches; \
                     pay each and call finalize_upload_merkle_multi() with one \
                     winner hash per batch."
                )));
            }
        }
        self.finalize_upload_merkle_multi_with_progress(
            prepared,
            vec![Some(winner_pool_hash)],
            progress,
        )
        .await
    }

    /// Phase 2 of external-signer upload (merkle): finalize with one winner
    /// pool hash per prepared sub-batch.
    ///
    /// `winner_pool_hashes` aligns with
    /// [`ExternalPaymentInfo::Merkle::prepared_batches`]: entry `i` is the
    /// `MerklePaymentMade` winner hash of batch `i`'s on-chain payment, or
    /// `None` if the signer never paid that batch (e.g. the user abandoned
    /// the flow midway). Paid batches make forward progress: their proofs
    /// are folded — mirroring the wallet path's multi-batch fold — and their
    /// chunks stored from the on-disk spill in a bounded fan-out; chunks of
    /// unpaid batches are reported through [`Error::PartialUpload`]
    /// (ADR-0003).
    ///
    /// # Errors
    ///
    /// Returns an error if the prepared upload used wave-batch payment, the
    /// hash count does not match the batch count, every entry is `None`, or
    /// proof generation fails. Chunks short of quorum after all retries —
    /// and all chunks of unpaid batches — surface as
    /// [`Error::PartialUpload`] carrying the stored and failed addresses.
    /// Re-preparing the same file skips chunks that are already stored.
    pub async fn finalize_upload_merkle_multi(
        &self,
        prepared: PreparedUpload,
        winner_pool_hashes: Vec<Option<[u8; 32]>>,
    ) -> Result<FileUploadResult> {
        self.finalize_upload_merkle_multi_with_progress(prepared, winner_pool_hashes, None)
            .await
    }

    /// Same as [`Client::finalize_upload_merkle_multi`] but emits
    /// [`UploadEvent::ChunkStored`] on the provided channel as each chunk is
    /// successfully stored.
    ///
    /// # Errors
    ///
    /// Same as [`Client::finalize_upload_merkle_multi`].
    pub async fn finalize_upload_merkle_multi_with_progress(
        &self,
        prepared: PreparedUpload,
        winner_pool_hashes: Vec<Option<[u8; 32]>>,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FileUploadResult> {
        let data_map_address = prepared.data_map_address;
        let already_stored_addresses = prepared.already_stored_addresses;
        let total_chunks = prepared.total_chunks;
        match prepared.payment_info {
            ExternalPaymentInfo::Merkle {
                prepared_batches,
                chunk_store,
                chunk_addresses,
            } => {
                let batch_result =
                    fold_external_merkle_payments(prepared_batches, winner_pool_hashes)?;

                let (chunks_stored, _storage_cost, _gas_cost, stats) = self
                    .upload_merkle_from_spill(
                        chunk_store.spill(),
                        &chunk_addresses,
                        &batch_result,
                        &already_stored_addresses,
                        progress.as_ref(),
                        // The external signer chose which sub-batches to pay.
                        // A refusal latched by some other operation on this
                        // client did not cause the gaps it left, and saying so
                        // would blame the wrong thing.
                        None,
                    )
                    .await?;

                info!("External-signer merkle upload finalized: {chunks_stored} chunks stored");

                Ok(FileUploadResult {
                    data_map: prepared.data_map,
                    chunks_stored,
                    chunks_failed: 0,
                    total_chunks,
                    payment_mode_used: PaymentMode::Merkle,
                    // The external signer pays on-chain out-of-band, so the
                    // spend is unknown to the library here.
                    storage_cost_atto: "0".into(),
                    gas_cost_wei: 0,
                    data_map_address,
                    chunk_attempts_total: stats.chunk_attempts_total,
                    store_durations_ms: stats.store_durations_ms,
                    retries_histogram: stats.retries_histogram,
                    // Envelope uploads are prepared as wave batches.
                    envelope: None,
                })
            }
            ExternalPaymentInfo::WaveBatch { .. } => Err(Error::Payment(
                "Cannot finalize wave-batch upload with merkle winner hashes. \
                 Use finalize_upload() instead."
                    .to_string(),
            )),
        }
    }

    /// Finalize an external-signer merkle upload, returning a resume handle if
    /// some chunks remain unstored after retries.
    ///
    /// Behaves like [`Client::finalize_upload_merkle_multi`], but instead of
    /// surfacing a quorum shortfall as [`Error::PartialUpload`] it returns
    /// [`FinalizeOutcome::Partial`], carrying a [`MerkleFinalizeResume`] (inside
    /// [`FinalizeResume::Merkle`]) that owns the on-disk chunk spill and the
    /// already-signed payment proofs. The caller can hand that handle to
    /// [`Client::finalize_resume`] to store only the still-unstored chunks
    /// against the **same** on-chain payment — no re-quoting, no second
    /// signature, no double payment (#140).
    ///
    /// Unlike the non-resumable method, **every sub-batch must be paid**
    /// (`winner_pool_hashes` all `Some`). A resume handle cannot acquire proofs
    /// for unpaid chunks, so a partially-paid finalize could never drain to
    /// [`FinalizeOutcome::Complete`]; partial payment is rejected up front. To
    /// finalize a partial payment, use [`Client::finalize_upload_merkle_multi`],
    /// which reports the unpaid chunks through [`Error::PartialUpload`].
    ///
    /// # Errors
    ///
    /// Returns an error if any sub-batch is unpaid, the winner-hash count does
    /// not match the prepared batches, the payment info is wave-batch rather
    /// than merkle, or payment finalization fails. Store failures are **not**
    /// errors here: a quorum shortfall — and a fatal store abort, which keeps
    /// its progress the same way — comes back as [`FinalizeOutcome::Partial`].
    pub async fn finalize_upload_merkle_multi_resumable(
        &self,
        prepared: PreparedUpload,
        winner_pool_hashes: Vec<Option<[u8; 32]>>,
    ) -> Result<FinalizeOutcome> {
        self.finalize_upload_merkle_multi_resumable_with_progress(
            prepared,
            winner_pool_hashes,
            None,
        )
        .await
    }

    /// Same as [`Client::finalize_upload_merkle_multi_resumable`] but emits
    /// [`UploadEvent::ChunkStored`] on the provided channel as each chunk is
    /// stored.
    ///
    /// # Errors
    ///
    /// Same as [`Client::finalize_upload_merkle_multi_resumable`].
    pub async fn finalize_upload_merkle_multi_resumable_with_progress(
        &self,
        prepared: PreparedUpload,
        winner_pool_hashes: Vec<Option<[u8; 32]>>,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FinalizeOutcome> {
        let data_map_address = prepared.data_map_address;
        let already_stored_addresses = prepared.already_stored_addresses;
        let total_chunks = prepared.total_chunks;
        let data_map = prepared.data_map;
        match prepared.payment_info {
            ExternalPaymentInfo::Merkle {
                prepared_batches,
                chunk_store,
                chunk_addresses,
            } => {
                require_fully_paid_for_resumable(&winner_pool_hashes)?;
                let batch_result =
                    fold_external_merkle_payments(prepared_batches, winner_pool_hashes)?;
                self.drive_merkle_finalize(
                    data_map,
                    data_map_address,
                    total_chunks,
                    chunk_store,
                    chunk_addresses,
                    batch_result,
                    already_stored_addresses,
                    progress.as_ref(),
                )
                .await
            }
            ExternalPaymentInfo::WaveBatch { .. } => Err(Error::Payment(
                "Cannot finalize wave-batch upload with merkle winner hashes. \
                 Use finalize_upload_resumable() instead."
                    .to_string(),
            )),
        }
    }

    /// Finalize an external-signer wave-batch upload, returning a resume handle
    /// if some chunks remain unstored after retries.
    ///
    /// Behaves like [`Client::finalize_upload`], but instead of surfacing a
    /// storage failure as [`Error::PartialUpload`] it returns
    /// [`FinalizeOutcome::Partial`], carrying a [`WaveFinalizeResume`] (inside
    /// [`FinalizeResume::Wave`]) that owns the already-paid chunks still needing
    /// storage. The caller can hand that handle to [`Client::finalize_resume`]
    /// to re-store only those chunks against the **same** on-chain payment — no
    /// re-quoting, no second signature, no double payment (#140).
    ///
    /// Paid quotes are read back first, as [`Client::finalize_upload`] reads
    /// them: a chunk whose quote was occupied is not sent, is counted failed,
    /// and is left out of the handle, which lists it
    /// ([`WaveFinalizeResume::occupied`]) and never completes the upload; the
    /// cost reported leaves the skipped payment out.
    ///
    /// # Errors
    ///
    /// Returns an error if a `tx_hash` is missing for a quote, the payment info
    /// is merkle rather than wave-batch, or payment finalization fails. A plain
    /// storage shortfall is **not** an error — it comes back as
    /// [`FinalizeOutcome::Partial`].
    pub async fn finalize_upload_resumable(
        &self,
        prepared: PreparedUpload,
        tx_hash_map: &HashMap<QuoteHash, TxHash>,
    ) -> Result<FinalizeOutcome> {
        self.finalize_upload_resumable_with_progress(prepared, tx_hash_map, None)
            .await
    }

    /// Same as [`Client::finalize_upload_resumable`] but emits
    /// [`UploadEvent::ChunkStored`] on the provided channel as each chunk is
    /// stored.
    ///
    /// # Errors
    ///
    /// Same as [`Client::finalize_upload_resumable`].
    pub async fn finalize_upload_resumable_with_progress(
        &self,
        prepared: PreparedUpload,
        tx_hash_map: &HashMap<QuoteHash, TxHash>,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FinalizeOutcome> {
        let data_map_address = prepared.data_map_address;
        let already_stored_count = prepared.already_stored_addresses.len();
        let total_chunks = prepared.total_chunks;
        let data_map = prepared.data_map;
        let envelope = prepared.envelope;
        match prepared.payment_info {
            ExternalPaymentInfo::WaveBatch {
                prepared_chunks,
                payment_intent,
            } => {
                let plans = plans_of(&prepared_chunks);
                let paid_chunks = finalize_batch_payment(prepared_chunks, tx_hash_map)?;
                let read_back = self
                    .read_back_outside_payment(&plans, paid_chunks, payment_intent.total_amount)
                    .await;
                Ok(self
                    .drive_wave_finalize(
                        data_map,
                        data_map_address,
                        total_chunks,
                        already_stored_count,
                        read_back.paid,
                        read_back.unpaid,
                        read_back.storage_cost_atto,
                        envelope,
                        progress.as_ref(),
                    )
                    .await)
            }
            ExternalPaymentInfo::Merkle { .. } => Err(Error::Payment(
                "Cannot finalize merkle upload with wave-batch tx hashes. \
                 Use finalize_upload_merkle_multi_resumable() instead."
                    .to_string(),
            )),
        }
    }

    /// Resume an external-signer finalize that returned
    /// [`FinalizeOutcome::Partial`], storing only the still-unstored chunks
    /// against the already-signed payment carried by the [`FinalizeResume`]
    /// handle.
    ///
    /// No re-quoting and no new signature: the handle owns the retained chunk
    /// bodies (wave path) or the spill + merkle proofs (merkle path). Every
    /// chunk in the handle has its payment material, so the upload always
    /// *can* complete once the network cooperates, unless the wave path's
    /// finalize found a chunk's paid quote occupied
    /// ([`WaveFinalizeResume::occupied`]): that chunk is not in the handle,
    /// every call reports it failed and holds the envelope back, and the
    /// upload has to be prepared again for it. Safe to call repeatedly —
    /// each call stores what it can and either completes the upload
    /// ([`FinalizeOutcome::Complete`]) or hands back the remainder, so a
    /// caller can loop until it drains or gives up (#140).
    ///
    /// **Bound that loop.** Store failures — including persistent ones, such
    /// as a chunk whose close group stays unreachable — surface as
    /// [`FinalizeOutcome::Partial`] on every call, never as `Err`, so an
    /// unbounded `while let Partial` loop will spin for as long as the
    /// failure persists. Cap the attempts (or apply backoff between them) and
    /// treat a handle that stops shrinking as stuck.
    ///
    /// # Errors
    ///
    /// Store failures are not errors — every store-side outcome, fatal aborts
    /// included, comes back as [`FinalizeOutcome::Partial`] with the payment
    /// material retained for retry. `Err` is reserved for failures outside
    /// the chunk store itself.
    pub async fn finalize_resume(&self, resume: FinalizeResume) -> Result<FinalizeOutcome> {
        self.finalize_resume_with_progress(resume, None).await
    }

    /// Same as [`Client::finalize_resume`] but emits [`UploadEvent::ChunkStored`]
    /// as each remaining chunk is stored.
    ///
    /// # Errors
    ///
    /// Same as [`Client::finalize_resume`].
    pub async fn finalize_resume_with_progress(
        &self,
        resume: FinalizeResume,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FinalizeOutcome> {
        match resume {
            FinalizeResume::Wave(w) => {
                let WaveFinalizeResume {
                    data_map,
                    data_map_address,
                    total_chunks,
                    stored_count,
                    failed_paid_chunks,
                    occupied,
                    storage_cost_atto,
                    envelope,
                } = *w;
                Ok(self
                    .drive_wave_finalize(
                        data_map,
                        data_map_address,
                        total_chunks,
                        stored_count,
                        failed_paid_chunks,
                        occupied,
                        storage_cost_atto,
                        envelope,
                        progress.as_ref(),
                    )
                    .await)
            }
            FinalizeResume::Merkle(m) => {
                let MerkleFinalizeResume {
                    data_map,
                    data_map_address,
                    total_chunks,
                    chunk_store,
                    unstored_addresses,
                    batch_result,
                    stored_addresses,
                } = *m;
                self.drive_merkle_finalize(
                    data_map,
                    data_map_address,
                    total_chunks,
                    chunk_store,
                    unstored_addresses,
                    batch_result,
                    stored_addresses,
                    progress.as_ref(),
                )
                .await
            }
        }
    }

    /// Drive one merkle store pass over `to_store` (reading bodies from the
    /// spill on demand and re-attaching proofs from `batch_result`), shared by
    /// the initial resumable finalize and [`Client::finalize_resume`].
    ///
    /// On a quorum shortfall — or a fatal store abort, which
    /// `upload_merkle_from_spill` folds into [`Error::PartialUpload`] with its
    /// progress preserved — it captures the retained spill, proofs, and the
    /// cumulative stored/unstored sets into a [`MerkleFinalizeResume`] and
    /// returns [`FinalizeOutcome::Partial`], so the same on-chain payment can
    /// be retried without re-signing. `Err` is reserved for failures outside
    /// the store fan-out (e.g. invalid payment material).
    #[allow(clippy::too_many_arguments)]
    async fn drive_merkle_finalize(
        &self,
        data_map: DataMap,
        data_map_address: Option<[u8; 32]>,
        total_chunks: usize,
        chunk_store: ExternalChunkStore,
        to_store: Vec<[u8; 32]>,
        batch_result: MerkleBatchPaymentResult,
        stored_addresses: Vec<[u8; 32]>,
        progress: Option<&mpsc::Sender<UploadEvent>>,
    ) -> Result<FinalizeOutcome> {
        let store_result = self
            .upload_merkle_from_spill(
                chunk_store.spill(),
                &to_store,
                &batch_result,
                &stored_addresses,
                progress,
                // External-signer payment material; see above.
                None,
            )
            .await;
        assemble_merkle_finalize_outcome(
            store_result,
            data_map,
            data_map_address,
            total_chunks,
            chunk_store,
            batch_result,
        )
    }

    /// Drive one wave-batch store pass over `paid_chunks`, shared by the initial
    /// resumable finalize and [`Client::finalize_resume`].
    ///
    /// Retains each paid chunk (cheaply — bodies are ref-counted `Bytes`) so a
    /// storage shortfall can hand the failed subset back in a
    /// [`WaveFinalizeResume`] ([`FinalizeOutcome::Partial`]) for re-store against
    /// the same payment, instead of the shortfall being dropped. The store never
    /// errors on a partial, so this is infallible.
    ///
    /// `occupied` lists the chunks whose paid quote the vault had recorded for
    /// another payment, with why ([`Client::read_back_outside_payment`]): they
    /// are never sent, every pass reports them failed, so the envelope is held
    /// back and the upload never completes on this payment, and the resume
    /// handle carries only that list for them, not their paid chunks.
    #[allow(clippy::too_many_arguments)]
    async fn drive_wave_finalize(
        &self,
        data_map: DataMap,
        data_map_address: Option<[u8; 32]>,
        total_chunks: usize,
        already_stored_count: usize,
        paid_chunks: Vec<PaidChunk>,
        occupied: Vec<([u8; 32], String)>,
        storage_cost_atto: String,
        envelope: Option<UploadEnvelope>,
        progress: Option<&mpsc::Sender<UploadEvent>>,
    ) -> FinalizeOutcome {
        // Retain address -> paid chunk so the failed subset can be re-stored on
        // resume; cloning is cheap since the chunk body is a ref-counted `Bytes`.
        let retained: HashMap<[u8; 32], PaidChunk> =
            paid_chunks.iter().map(|c| (c.address, c.clone())).collect();
        let envelope_proof = envelope_payment_proof(envelope.as_ref(), &paid_chunks);
        let wave_result = self
            .store_paid_chunks_then(
                paid_chunks,
                envelope.as_ref().map(UploadEnvelope::address),
                occupied.clone(),
                progress,
                already_stored_count,
                total_chunks,
            )
            .await;
        let mut outcome = assemble_wave_finalize_outcome(
            wave_result,
            retained,
            occupied,
            data_map,
            data_map_address,
            total_chunks,
            already_stored_count,
            storage_cost_atto,
        );
        // The envelope (stored last) goes with the result, its record filled
        // in once every chunk is stored, so reading the chain never stands
        // between a paid upload and storing it. A partial one goes with the
        // resume handle too, so a resume stores it last again.
        match &mut outcome {
            FinalizeOutcome::Complete(result) => {
                if let Some(mut envelope) = envelope {
                    self.complete_external_envelope(
                        &mut envelope,
                        &result.data_map,
                        envelope_proof.as_deref(),
                    )
                    .await;
                    result.envelope = Some(envelope);
                }
            }
            FinalizeOutcome::Partial { result, resume } => {
                result.envelope.clone_from(&envelope);
                if let FinalizeResume::Wave(resume) = resume {
                    resume.envelope = envelope;
                }
            }
        }
        outcome
    }

    /// Store `paid_chunks`, the one at `last` (an envelope) only once every
    /// other chunk is stored, so it never points at missing content. If any
    /// other chunk fails, or `failed_before` names chunks of the upload that
    /// can't be stored (reported failed first, as they are), `last` is
    /// reported failed without being sent.
    async fn store_paid_chunks_then(
        &self,
        paid_chunks: Vec<PaidChunk>,
        last: Option<[u8; 32]>,
        failed_before: Vec<([u8; 32], String)>,
        progress: Option<&mpsc::Sender<UploadEvent>>,
        stored_before: usize,
        total_chunks: usize,
    ) -> WaveResult {
        let (held, others): (Vec<_>, Vec<_>) = paid_chunks
            .into_iter()
            .partition(|chunk| Some(chunk.address) == last);
        let mut result = self
            .store_paid_chunks_with_events(others, progress, stored_before, total_chunks)
            .await;
        let stored_failures = std::mem::replace(&mut result.failed, failed_before);
        result.failed.extend(stored_failures);
        // Paid chunks are unique by address, so at most one is held.
        let Some(held) = super::super::upload::release_last(
            held.into_iter().next(),
            |chunk: &PaidChunk| chunk.address,
            &mut result.failed,
        ) else {
            return result;
        };
        let stored_before = stored_before + result.stored.len();
        let last = self
            .store_paid_chunks_with_events(vec![held], progress, stored_before, total_chunks)
            .await;
        result.stored.extend(last.stored);
        result.failed.extend(last.failed);
        result.chunk_attempts_total += last.chunk_attempts_total;
        result.store_durations_ms.extend(last.store_durations_ms);
        result.retries_per_chunk.extend(last.retries_per_chunk);
        result
    }

    /// Read back the vault record of every quote an outside payer paid for
    /// `paid_chunks` (`plans`, from the prepared chunks), before any chunk is
    /// sent, and set aside each chunk whose quote the vault had recorded for
    /// another payment first. The vault skipped that payment, which moved no
    /// tokens, so nodes would refuse the chunk, and a finalize can't quote it
    /// again: it fails, naming the node that issued the quote. `paid_total`
    /// is the payment intent's total.
    async fn read_back_outside_payment(
        &self,
        plans: &[ChunkPaymentPlan],
        paid_chunks: Vec<PaidChunk>,
        paid_total: Amount,
    ) -> OutsidePaymentReadBack {
        let occupied = self.occupied_quotes(plans).await;
        let reason = (!occupied.is_empty()).then(|| {
            let reason = occupied_at_finalize(&occupied).to_string();
            warn!("{reason}");
            reason
        });
        let (paid, unpaid) = set_aside_occupied(paid_chunks, &occupied);
        OutsidePaymentReadBack {
            paid,
            unpaid,
            storage_cost_atto: paid_total
                .saturating_sub(skipped_amount(&occupied))
                .to_string(),
            reason,
        }
    }

    /// Fill in an external-signer upload's envelope record, once every chunk
    /// is stored, from the payment proof of its paid chunk (`proof`; `None`
    /// if it was already stored when the upload was prepared). Never fails:
    /// the upload is paid and stored by now, and a client without an EVM
    /// network builds the record unchecked.
    async fn complete_external_envelope(
        &self,
        envelope: &mut UploadEnvelope,
        data_map: &DataMap,
        proof: Option<&[u8]>,
    ) {
        let network = self.require_evm_network().ok();
        self.complete_upload_envelope(envelope, data_map, proof, network)
            .await;
    }

    /// Upload a file with a specific payment mode, in the private envelope
    /// [`Client::file_upload`] stores.
    ///
    /// Before encryption, checks that the temp directory has enough free
    /// disk space for the spilled chunks (~1.1× source file size).
    ///
    /// Encrypted chunks are spilled to a temp directory during encryption
    /// so that only their 32-byte addresses stay in memory. At upload time,
    /// chunks are read back one wave at a time (~64 × 4 MB ≈ 256 MB peak).
    ///
    /// # Errors
    ///
    /// Returns an error if there is insufficient disk space, the file cannot
    /// be read, encryption fails, or any chunk cannot be stored.
    #[allow(clippy::too_many_lines)]
    pub async fn file_upload_with_mode(
        &self,
        path: &Path,
        mode: PaymentMode,
    ) -> Result<FileUploadResult> {
        self.file_upload_with_progress(path, mode, None).await
    }

    /// Upload a file readable by anyone with its address, in the unlisted
    /// envelope `darwin file upload --public` stores: the [`DataMap`] in an
    /// envelope that shows every payment field, not in the index, paid with
    /// the content.
    ///
    /// The returned [`FileUploadResult::data_map_address`] is the envelope's
    /// address; share it for public downloads via [`Client::data_map_fetch`],
    /// which reads the data map from the envelope. The envelope and its
    /// record are in [`FileUploadResult::envelope`].
    #[allow(clippy::too_many_lines)]
    pub async fn file_upload_public_with_mode(
        &self,
        path: &Path,
        mode: PaymentMode,
    ) -> Result<FileUploadResult> {
        self.file_upload_with_visibility_and_progress(
            path,
            mode,
            super::super::envelope::public_shortcut_visibility(),
            None,
        )
        .await
    }

    /// Upload a file with progress events sent to the given channel.
    ///
    /// Same as [`Client::file_upload_with_mode`] but sends [`UploadEvent`]s to the
    /// provided channel for UI progress feedback.
    #[allow(clippy::too_many_lines)]
    pub async fn file_upload_with_progress(
        &self,
        path: &Path,
        mode: PaymentMode,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FileUploadResult> {
        self.file_upload_with_visibility_and_progress(
            path,
            mode,
            super::super::envelope::private_shortcut_visibility(),
            progress,
        )
        .await
    }

    /// Upload a file with the given [`Visibility`], with progress events.
    ///
    /// An envelope upload ([`Visibility::Envelope`]) stores the envelope in
    /// the same payment as the content where the content is paid per chunk
    /// (every upload under 64 chunks, and the chunks left after the merkle
    /// batches of a larger one; alone if there are none), after every
    /// content chunk is stored. [`FileUploadResult::envelope`] carries the
    /// envelope, the salt of a private one and its proof record. The record
    /// (or, without one, a private envelope's salt) is also kept under the
    /// client's data directory until the caller has saved it and calls
    /// [`forget_upload_record`]. An upload that finds its envelope already
    /// stored by an earlier upload of the same file, with the same choices
    /// and wallet, gets that upload's kept record back if it is still there.
    pub async fn file_upload_with_visibility_and_progress(
        &self,
        path: &Path,
        mode: PaymentMode,
        visibility: Visibility,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FileUploadResult> {
        self.upload_file(path, mode, visibility, progress, None)
            .await
    }

    /// Upload a file paid by `payer` instead of the client's wallet, for
    /// example an agent paying from its own account. The client needs an EVM
    /// network ([`Client::with_evm_network`]) but no wallet.
    ///
    /// Uses the same engine as the wallet uploads: chunks are spilled to disk,
    /// and a checkpoint saved before every payment lets an interrupted upload
    /// resume (the payer is then asked to recover the same payment) without
    /// paying twice. In [`PaymentMode::Merkle`] a network too small for a batch
    /// payment, or one whose nodes refuse batch payments
    /// ([`Error::BatchPaymentsRefused`], as darwin-node's do), fails before
    /// any payment; [`PaymentMode::Auto`] falls back to per-chunk payments.
    /// An envelope upload is paid and stored as
    /// [`Client::file_upload_with_visibility_and_progress`] describes. The
    /// upload's checkpoint, and an envelope upload's kept record, belong to
    /// the payer ([`UploadPayer::checkpoint_scope`]), so a payer serving
    /// several accounts must name each.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or encrypted, a payment
    /// fails, or any chunk cannot be stored.
    pub async fn file_upload_with_payer(
        &self,
        path: &Path,
        visibility: Visibility,
        mode: PaymentMode,
        payer: &dyn UploadPayer,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FileUploadResult> {
        self.upload_file(path, mode, visibility, progress, Some(payer))
            .await
    }

    /// Public file upload with progress events, in the unlisted envelope
    /// [`Client::file_upload_public_with_mode`] stores.
    ///
    /// Same as [`Client::file_upload_public_with_mode`] but sends
    /// [`UploadEvent`]s to the provided channel for UI progress feedback.
    #[allow(clippy::too_many_lines)]
    pub async fn file_upload_public_with_progress(
        &self,
        path: &Path,
        mode: PaymentMode,
        progress: Option<mpsc::Sender<UploadEvent>>,
    ) -> Result<FileUploadResult> {
        self.file_upload_with_visibility_and_progress(
            path,
            mode,
            super::super::envelope::public_shortcut_visibility(),
            progress,
        )
        .await
    }

    /// Upload a file through the upload engine, paid by `payer` or else by
    /// the client's wallet.
    #[allow(clippy::too_many_lines)]
    async fn upload_file(
        &self,
        path: &Path,
        mode: PaymentMode,
        visibility: Visibility,
        progress: Option<mpsc::Sender<UploadEvent>>,
        payer: Option<&dyn UploadPayer>,
    ) -> Result<FileUploadResult> {
        let visibility = visibility.normalized();
        check_envelope_options(&visibility)?;
        debug!(
            "Streaming file upload with mode {mode:?}, visibility {visibility:?}: {}",
            path.display()
        );

        // Pre-flight: verify enough temp disk space for the chunk spill.
        let file_size = std::fs::metadata(path)?.len();
        check_disk_space_for_spill(file_size)?;

        // Phase 1: Encrypt file and spill chunks to temp directory.
        // Only 32-byte addresses stay in memory — chunk data lives on disk.
        let (mut spill, data_map) = self.encrypt_file_to_spill(path, progress.as_ref()).await?;

        let mut data_map_address = match visibility {
            Visibility::Public => {
                let (address, serialized) =
                    crate::client_engine::files::public_map_record(&data_map)
                        .map_err(Error::Serialization)?;
                info!(
                    "Public upload: adding DataMap chunk ({} bytes) at address {} to payment batch",
                    serialized.len(),
                    hex::encode(address)
                );
                spill.push(&serialized)?;
                Some(address)
            }
            Visibility::Private | Visibility::Envelope(_) => None,
        };

        let file_path_key = std::fs::canonicalize(path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string());
        // An envelope is not among these: it is added below, stored last.
        let records = spill
            .chunk_entries()?
            .into_iter()
            .enumerate()
            .map(
                |(index, (address, size))| super::super::upload::UploadRecord {
                    address,
                    size,
                    index,
                },
            )
            .collect::<Vec<_>>();
        let (network, payer_scope) = match payer {
            Some(payer) => (self.require_evm_network()?, payer.checkpoint_scope()),
            None => {
                let wallet = self.require_wallet()?;
                (wallet.network(), wallet.address().as_slice().to_vec())
            }
        };
        let envelope_scope = visibility
            .envelope_options()
            .map(|options| envelope_checkpoint_scope(options, &payer_scope));
        let (cache_path, _lock, saved) = open_upload_checkpoint(
            network,
            &records,
            envelope_scope.as_deref(),
            payer.map(|_| payer_scope.as_slice()),
        )
        .await?;
        let mut envelope = match &visibility {
            Visibility::Envelope(options) => {
                let salt = if options.readable {
                    None
                } else {
                    Some(upload_salt(&cache_path)?)
                };
                let (envelope, serialized) = build_upload_envelope(options, &data_map, salt)?;
                spill.push(&serialized)?;
                if options.readable {
                    data_map_address = Some(envelope.address());
                }
                let record = super::super::upload::UploadRecord {
                    address: envelope.address(),
                    size: serialized.len() as u64,
                    index: records.len(),
                };
                Some((envelope, record))
            }
            _ => None,
        };

        let chunk_count = spill.len();
        info!(
            "Encrypted {} into {chunk_count} chunks (spilled to disk)",
            path.display()
        );
        if let Some(ref tx) = progress {
            let _ = tx
                .send(UploadEvent::Encrypted {
                    total_chunks: chunk_count,
                })
                .await;
        }

        let mut state = match saved {
            Some(state) => state,
            None => {
                let mut proofs =
                    crate::data::client::cached_single::try_load_for_file(&file_path_key)
                        .map(|(_, receipt)| receipt.proofs)
                        .unwrap_or_default();
                if let Some((_, receipt)) =
                    crate::data::client::cached_merkle::try_load_for_file(&file_path_key)
                {
                    proofs.extend(receipt.proofs);
                }
                super::super::upload_state::UploadState::from_proofs(proofs)
            }
        };
        let adapter = SpillUploadAdapter {
            client: self,
            source: ChunkSource::Spill(&spill),
            progress: progress.as_ref(),
            checkpoint: &cache_path,
            payer,
        };
        // A payment this wallet sent may have gone through although the RPC
        // answered with an error. Its signed transaction is in the journal,
        // and running the upload again reconciles it from the chain before
        // anything is paid, so do that once here rather than leave it to the
        // user. Only for this wallet's own payments: an external payer would
        // be asked to pay again.
        let mut rechecked = false;
        let mut recovered = Amount::ZERO;
        let mut result = loop {
            let attempt = match envelope.as_ref() {
                Some((_, last)) => {
                    self.upload_records_then(records.clone(), *last, &mut state, &adapter, mode)
                        .await
                }
                None => {
                    self.upload_records(records.clone(), &mut state, &adapter, mode)
                        .await
                }
            };
            match attempt {
                Err(error) if !rechecked && payer.is_none() && payment_outcome_unknown(&state) => {
                    rechecked = true;
                    recovered = unresolved_payment_amount(&state);
                    warn!(
                        "Payment outcome unknown ({error}); checking the chain in {}s before giving up",
                        PAYMENT_RECHECK_DELAY.as_secs()
                    );
                    tokio::time::sleep(PAYMENT_RECHECK_DELAY).await;
                }
                attempt => break attempt?,
            }
        };
        // A payment recovered from the chain was sent by this upload, so it
        // counts in its cost. If the retry paid instead (the first payment
        // never landed), that payment is already counted.
        if result.amount == Amount::ZERO {
            result.amount = recovered;
        }
        // The record is built before the checkpoint is removed, and kept
        // until the caller has saved it.
        if let Some((envelope, _)) = envelope.as_mut() {
            let proof = state.proof(&envelope.address()).cloned();
            // Without a payment of its own the envelope was already stored:
            // by this payer's earlier upload, if it kept a record for it.
            let kept = proof.is_none().then(|| {
                cache_path
                    .parent()
                    .and_then(|directory| kept_upload_record(directory, envelope, &payer_scope))
            });
            match kept.flatten() {
                Some(record) => self.reuse_upload_record(envelope, record, network).await,
                None => {
                    self.complete_upload_envelope(
                        envelope,
                        &data_map,
                        proof.as_deref(),
                        Some(network),
                    )
                    .await;
                }
            }
        }
        finish_upload_checkpoint(
            &cache_path,
            envelope.as_ref().map(|(envelope, _)| envelope),
            &payer_scope,
        );
        crate::data::client::cached_single::try_delete_for_file(&file_path_key);
        crate::data::client::cached_merkle::try_delete_for_file(&file_path_key);
        Ok(FileUploadResult {
            data_map,
            chunks_stored: result.addresses.len(),
            chunks_failed: 0,
            total_chunks: chunk_count,
            payment_mode_used: result.mode,
            storage_cost_atto: result.amount.to_string(),
            gas_cost_wei: result.gas,
            data_map_address,
            chunk_attempts_total: result.stats.chunk_attempts_total,
            store_durations_ms: result.stats.store_durations_ms,
            retries_histogram: result.stats.retries_histogram,
            envelope: envelope.map(|(envelope, _)| envelope),
        })
    }

    /// Encrypt a file and spill chunks to a temp directory.
    ///
    /// Logs progress every 100 chunks so users get feedback during
    /// multi-GB encryptions.
    ///
    /// Returns the spill buffer (addresses on disk) and the `DataMap`.
    async fn encrypt_file_to_spill(
        &self,
        path: &Path,
        progress: Option<&mpsc::Sender<UploadEvent>>,
    ) -> Result<(ChunkSpill, DataMap)> {
        let (mut chunk_rx, datamap_rx, handle) = spawn_file_encryption(path.to_path_buf())?;

        let mut spill = ChunkSpill::new()?;
        while let Some(content) = chunk_rx.recv().await {
            spill.push(&content)?;
            let chunks_done = spill.len();
            if let Some(tx) = progress {
                if chunks_done.is_multiple_of(10) {
                    let _ = tx.send(UploadEvent::Encrypting { chunks_done }).await;
                }
            }
            if chunks_done % 100 == 0 {
                let mb = spill.total_bytes() / (1024 * 1024);
                info!(
                    "Encryption progress: {chunks_done} chunks spilled ({mb} MB) — {}",
                    path.display()
                );
            }
        }

        // Await encryption completion to catch errors before paying.
        handle
            .await
            .map_err(|e| Error::Encryption(format!("encryption task panicked: {e}")))?
            .map_err(|e| Error::Encryption(format!("encryption failed: {e}")))?;

        let data_map = datamap_rx
            .await
            .map_err(|_| Error::Encryption("no DataMap from encryption thread".to_string()))?;

        Ok((spill, data_map))
    }

    /// Download and decrypt a file, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if a chunk cannot be retrieved, decryption fails,
    /// or the file cannot be written.
    pub async fn file_download(&self, data_map: &DataMap, output: &Path) -> Result<u64> {
        self.file_download_with_progress(data_map, output, None)
            .await
    }

    /// Download and decrypt a file, trying the requested number of
    /// closest peers for every chunk fetch.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if any chunk cannot be retrieved, decryption fails,
    /// or the file cannot be written.
    pub async fn file_download_from_closest_peers(
        &self,
        data_map: &DataMap,
        output: &Path,
        peer_count: NonZeroUsize,
    ) -> Result<u64> {
        self.file_download_with_progress_from_closest_peers(data_map, output, None, peer_count)
            .await
    }

    /// Download and decrypt a file with progress events, trying the
    /// requested number of closest peers for every chunk fetch.
    ///
    /// Same as [`Client::file_download_from_closest_peers`] but sends
    /// [`DownloadEvent`]s for UI feedback.
    ///
    /// # Errors
    ///
    /// Returns an error if any chunk cannot be retrieved, decryption fails,
    /// or the file cannot be written.
    pub async fn file_download_with_progress_from_closest_peers(
        &self,
        data_map: &DataMap,
        output: &Path,
        progress: Option<mpsc::Sender<DownloadEvent>>,
        peer_count: NonZeroUsize,
    ) -> Result<u64> {
        self.file_download_with_progress_using_peer_count(
            data_map,
            output,
            progress,
            peer_count.get(),
            None,
        )
        .await
    }

    /// Download a file with progress and optional per-attempt JSONL diagnostics.
    ///
    /// Passing `None` preserves the standard path without diagnostic records.
    pub async fn file_download_with_progress_and_diagnostics_from_closest_peers(
        &self,
        data_map: &DataMap,
        output: &Path,
        progress: Option<mpsc::Sender<DownloadEvent>>,
        peer_count: NonZeroUsize,
        diagnostics: Option<DownloadDiagnosticsSender>,
    ) -> Result<u64> {
        self.file_download_with_progress_using_peer_count(
            data_map,
            output,
            progress,
            peer_count.get(),
            diagnostics,
        )
        .await
    }

    /// Download and decrypt a file with peer-health diagnostics.
    ///
    /// Each file chunk is fetched by querying every selected closest peer,
    /// not by returning after the first successful peer. The returned report
    /// records which peers had each chunk and which did not. DataMap
    /// resolution still uses the normal early-return fetch path; diagnostics
    /// are for file chunks only.
    ///
    /// # Errors
    ///
    /// Returns an error if any chunk cannot be retrieved, decryption fails,
    /// or the file cannot be written.
    pub async fn file_download_with_peer_report_from_closest_peers(
        &self,
        data_map: &DataMap,
        output: &Path,
        progress: Option<mpsc::Sender<DownloadEvent>>,
        peer_count: NonZeroUsize,
    ) -> Result<FileDownloadWithPeerReport> {
        let chunk_reports = Arc::new(Mutex::new(Vec::new()));
        let bytes_written = self
            .file_download_with_progress_using_peer_count_and_reports(
                data_map,
                output,
                progress,
                peer_count.get(),
                Some(chunk_reports.clone()),
                None,
            )
            .await?;

        let chunk_reports = chunk_reports
            .lock()
            .map_err(|_| Error::Storage("file chunk peer report lock poisoned".to_string()))?
            .clone();
        let chunk_reports = file_chunk_reports_from_recorded_sweeps(chunk_reports);

        Ok(FileDownloadWithPeerReport {
            bytes_written,
            chunk_reports,
        })
    }

    async fn download_fetch_file_chunk(
        &self,
        idx: usize,
        hash: XorName,
        context: FileDownloadFetchContext,
        is_deferred_retry: bool,
        attempt: usize,
    ) -> std::result::Result<DownloadBatchEntry, self_encryption::Error> {
        let addr = hash.0;
        let addr_hex = hex::encode(addr);

        let chunk_content = if let Some(peer_reports) = context.peer_reports {
            match self
                .chunk_get_from_closest_peer_group(&addr, context.peer_count)
                .await
            {
                Ok(results) => {
                    let (content, sweep) = file_chunk_sweep_report_from_peer_results(
                        attempt,
                        is_deferred_retry,
                        &results,
                    );
                    peer_reports
                        .lock()
                        .map_err(|_| {
                            self_encryption::Error::Generic(
                                "file chunk peer report lock poisoned".to_string(),
                            )
                        })?
                        .push(RecordedFileChunkPeerSweep {
                            index: idx + 1,
                            address: addr,
                            sweep,
                        });
                    content
                }
                Err(e) => {
                    if is_deferred_retry {
                        info!(
                            "Deferred all-peer retry for {addr_hex} hit transient error: {e}; re-deferring"
                        );
                    } else {
                        info!("First-pass all-peer fetch error for {addr_hex}: {e}; deferring");
                    }
                    peer_reports
                        .lock()
                        .map_err(|_| {
                            self_encryption::Error::Generic(
                                "file chunk peer report lock poisoned".to_string(),
                            )
                        })?
                        .push(RecordedFileChunkPeerSweep {
                            index: idx + 1,
                            address: addr,
                            sweep: file_chunk_sweep_report_from_error(
                                attempt,
                                is_deferred_retry,
                                &e,
                            ),
                        });
                    None
                }
            }
        } else {
            // Normal path: early-return after the first peer that has the
            // chunk. When diagnostics are enabled we thread a per-chunk
            // diagnostics context through so each peer attempt in the sweep
            // is recorded; when disabled (`None`) this is a zero-cost pass.
            let diag = context.diagnostics.as_ref().map(|sender| {
                ChunkFetchDiagnostics::new(
                    sender,
                    attempt,
                    idx + 1,
                    addr,
                    self.controller().fetch.current(),
                )
            });
            match self
                .chunk_get_observed_from_closest_peers(&addr, context.peer_count, diag.as_ref())
                .await
            {
                Ok(Some(chunk)) => Some(chunk.content),
                Ok(None) => None,
                Err(e) => {
                    if is_deferred_retry {
                        info!(
                            "Deferred retry for {addr_hex} hit transient error: {e}; re-deferring"
                        );
                    } else {
                        info!("First-pass fetch error for {addr_hex}: {e}; deferring");
                    }
                    None
                }
            }
        };

        let Some(content) = chunk_content else {
            return Ok((idx, Err(hash)));
        };

        let fetched = context
            .fetched_ref
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if is_deferred_retry {
            info!(
                "Downloaded {fetched}/{} (deferred retry)",
                context.total_chunks
            );
        } else {
            let total_chunks = context.total_chunks;
            info!("Downloaded {fetched}/{total_chunks}");
        }
        if let Some(ref tx) = context.progress_ref {
            let _ = tx.try_send(DownloadEvent::ChunksFetched {
                fetched,
                total: context.total_chunks,
            });
        }

        Ok((idx, Ok(content)))
    }

    /// Shared download core: resolve the DataMap, then fetch + streaming-decrypt
    /// the file one batch at a time, handing each decrypted plaintext segment
    /// (in order) to `on_chunk`. Constant memory — only one decrypt batch is
    /// resident at a time. Returns the total plaintext bytes produced.
    ///
    /// `on_chunk` is async so a sink can apply backpressure (e.g. a bounded
    /// channel). Driving the decrypt iterator runs the batched chunk fetch via
    /// `block_in_place`, so this requires a multi-threaded Tokio runtime.
    ///
    /// Every chunk fetch tries `peer_count` closest peers.
    ///
    /// Progress reporting (via `progress`):
    /// 1. Resolves hierarchical DataMaps to the root level first (reports as
    ///    `ChunksFetched` with `total: 0` during resolution)
    /// 2. Once the root DataMap is known, sends `total_chunks` with accurate count
    /// 3. Fetches data chunks with accurate `fetched/total` progress
    async fn download_decrypted_chunks<F, Fut>(
        &self,
        data_map: &DataMap,
        progress: Option<mpsc::Sender<DownloadEvent>>,
        peer_count: usize,
        peer_reports: Option<Arc<Mutex<Vec<RecordedFileChunkPeerSweep>>>>,
        diagnostics: Option<DownloadDiagnosticsSender>,
        mut on_chunk: F,
    ) -> Result<u64>
    where
        F: FnMut(Bytes) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let handle = Handle::current();

        // Phase 1: Resolve hierarchical DataMap to root level.
        // This fetches child DataMap chunks (typically 3) to discover the real chunk count.
        let root_map = if data_map.is_child() {
            let dm_chunks = data_map.len();
            if let Some(ref tx) = progress {
                let _ = tx.try_send(DownloadEvent::ResolvingDataMap {
                    total_map_chunks: dm_chunks,
                });
            }

            let resolve_counter = std::sync::atomic::AtomicUsize::new(0);
            let resolved = crate::client_engine::files::resolve(
                data_map,
                &|address| {
                    let resolve_counter = &resolve_counter;
                    let progress = &progress;
                    let diagnostics = &diagnostics;
                    async move {
                        let diag = diagnostics.as_ref().map(|sender| {
                            ChunkFetchDiagnostics::new(
                                sender,
                                FIRST_DIAGNOSTIC_FETCH_ATTEMPT,
                                0,
                                address,
                                self.controller().fetch.current(),
                            )
                        });
                        let chunk = self
                            .chunk_get_observed_from_closest_peers(
                                &address,
                                peer_count,
                                diag.as_ref(),
                            )
                            .await?
                            .ok_or_else(|| {
                                Error::NotFound(format!(
                                    "DataMap chunk not found: {}",
                                    hex::encode(address)
                                ))
                            })?;
                        let fetched =
                            resolve_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        if let Some(ref tx) = progress {
                            let _ = tx.try_send(DownloadEvent::MapChunkFetched { fetched });
                        }
                        Ok(chunk.content)
                    }
                },
                &|| self.controller().fetch.current(),
            )
            .await
            .map_err(super::super::data::map_read_error)?;

            info!(
                "Resolved hierarchical DataMap: {} data chunks",
                resolved.len()
            );
            resolved
        } else {
            data_map.clone()
        };

        // Phase 2: Now we know the real chunk count.
        let total_chunks = root_map.len();
        if let Some(ref tx) = progress {
            let _ = tx.try_send(DownloadEvent::DataMapResolved { total_chunks });
        }

        // Phase 3: Fetch and decrypt data chunks with accurate progress.
        let fetched_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetched_for_closure = fetched_counter.clone();
        let progress_for_closure = progress.clone();
        let peer_reports_for_closure = peer_reports.clone();
        let diagnostics_for_closure = diagnostics.clone();

        let fetch_limiter_outer = self.controller().fetch.clone();
        let usable_memory = self
            .config()
            .download_memory_bytes
            .or_else(usable_memory_bytes);
        let configured_batch_floor = stream_decrypt_batch_size();
        let fetch_cap = fetch_limiter_outer.current();
        let decrypt_batch_size = adaptive_stream_decrypt_batch_size(
            total_chunks,
            fetch_cap,
            configured_batch_floor,
            usable_memory,
        );
        info!(
            total_chunks,
            fetch_cap,
            configured_batch_floor,
            ?usable_memory,
            decrypt_batch_size,
            "Selected adaptive stream decrypt batch size"
        );

        let stream = streaming_decrypt_with_batch_size(
            &root_map,
            |batch: &[(usize, XorName)]| {
                let batch_owned: Vec<(usize, XorName)> = batch.to_vec();
                let fetch_context = FileDownloadFetchContext {
                    total_chunks,
                    peer_count,
                    fetched_ref: fetched_for_closure.clone(),
                    progress_ref: progress_for_closure.clone(),
                    peer_reports: peer_reports_for_closure.clone(),
                    diagnostics: diagnostics_for_closure.clone(),
                };
                let fetch_limiter = fetch_limiter_outer.clone();

                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        crate::client_engine::files::deferred_batch(
                            batch_owned,
                            |idx, hash, attempt| {
                                self.download_fetch_file_chunk(
                                    idx,
                                    hash,
                                    fetch_context.clone(),
                                    attempt > 1,
                                    attempt,
                                )
                            },
                            || fetch_limiter.current(),
                            tokio::time::sleep,
                            |hash: XorName| {
                                self_encryption::Error::Generic(format!(
                                    "Chunk not found after 3 deferred retry rounds: {}",
                                    hex::encode(hash.0),
                                ))
                            },
                        )
                        .await
                    })
                })
            },
            decrypt_batch_size,
        )
        .map_err(|e| Error::Encryption(format!("streaming decrypt failed: {e}")))?;

        // Drive the iterator (each `next()` runs the batched fetch via
        // block_in_place) and hand each decrypted segment to the sink in
        // order. Awaiting the sink between items yields back to the runtime so
        // a bounded sink can apply backpressure.
        let mut bytes_total = 0u64;
        for chunk_result in stream {
            let chunk: Bytes =
                chunk_result.map_err(|e| Error::Encryption(format!("decryption failed: {e}")))?;
            bytes_total += chunk.len() as u64;
            on_chunk(chunk).await?;
        }
        Ok(bytes_total)
    }

    /// Download and decrypt a file to disk, with optional progress events.
    ///
    /// Same as [`Client::file_download`] but sends [`DownloadEvent`]s for UI
    /// feedback. Streams to a temp file (one decrypt batch resident at a time)
    /// and renames atomically on success. A `TempDownload` guard removes the
    /// staging file on any error path, including a panic.
    pub async fn file_download_with_progress(
        &self,
        data_map: &DataMap,
        output: &Path,
        progress: Option<mpsc::Sender<DownloadEvent>>,
    ) -> Result<u64> {
        self.file_download_with_progress_using_peer_count(
            data_map,
            output,
            progress,
            self.config().close_group_size,
            None,
        )
        .await
    }

    /// Download and decrypt a file to disk with progress events, trying
    /// `peer_count` closest peers for every chunk fetch.
    ///
    /// Streams to a temp file (one decrypt batch resident at a time) and
    /// renames atomically on success.
    async fn file_download_with_progress_using_peer_count(
        &self,
        data_map: &DataMap,
        output: &Path,
        progress: Option<mpsc::Sender<DownloadEvent>>,
        peer_count: usize,
        diagnostics: Option<DownloadDiagnosticsSender>,
    ) -> Result<u64> {
        self.file_download_with_progress_using_peer_count_and_reports(
            data_map,
            output,
            progress,
            peer_count,
            None,
            diagnostics,
        )
        .await
    }

    async fn file_download_with_progress_using_peer_count_and_reports(
        &self,
        data_map: &DataMap,
        output: &Path,
        progress: Option<mpsc::Sender<DownloadEvent>>,
        peer_count: usize,
        peer_reports: Option<Arc<Mutex<Vec<RecordedFileChunkPeerSweep>>>>,
        diagnostics: Option<DownloadDiagnosticsSender>,
    ) -> Result<u64> {
        debug!("Downloading file to {}", output.display());

        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        let unique: u64 = rand::random();
        let tmp_path = parent.join(format!(".ant_download_{}_{unique}.tmp", std::process::id()));

        // Guard removes the staging file on any early return OR a panic unwind
        // out of the `block_in_place` decrypt loop; defused only by a
        // successful commit(). Centralizes what used to be three duplicated
        // cleanup arms.
        let tmp = TempDownload::new(tmp_path);
        let mut file = std::fs::File::create(tmp.path())?;

        let bytes_written = self
            .download_decrypted_chunks(
                data_map,
                progress,
                peer_count,
                peer_reports,
                diagnostics,
                |bytes| {
                    let r = file.write_all(&bytes).map_err(Error::from);
                    std::future::ready(r)
                },
            )
            .await?;
        file.flush()?;
        drop(file); // close the handle before rename (Windows won't rename an open file)

        tmp.commit(output)?;
        info!(
            "File downloaded: {bytes_written} bytes written to {}",
            output.display()
        );
        Ok(bytes_written)
    }

    /// Download and decrypt a file, streaming the plaintext to `sink` instead
    /// of writing to disk.
    ///
    /// Constant memory (one decrypt batch resident at a time); the caller
    /// receives bytes progressively as each batch decrypts, suitable for
    /// forwarding to an HTTP chunked body or a gRPC response stream. The
    /// bounded `sink` applies backpressure. If the receiver is dropped (e.g.
    /// the client disconnected) the download stops early and returns
    /// [`Error::Cancelled`].
    ///
    /// The channel item type is `Result<Bytes, Error>`, so the caller sets up:
    ///
    /// ```ignore
    /// let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Error>>(8);
    /// ```
    ///
    /// Typically the caller `tokio::spawn`s this and converts the matching
    /// `Receiver` into its response stream. Requires a multi-threaded Tokio
    /// runtime (the decrypt iterator uses `block_in_place`).
    pub async fn file_download_to_sender(
        &self,
        data_map: &DataMap,
        sink: mpsc::Sender<std::result::Result<Bytes, Error>>,
        progress: Option<mpsc::Sender<DownloadEvent>>,
    ) -> Result<u64> {
        let peer_count = self.config().close_group_size;
        self.download_decrypted_chunks(data_map, progress, peer_count, None, None, |bytes| {
            let sink = sink.clone();
            async move {
                sink.send(Ok(bytes))
                    .await
                    .map_err(|_| Error::Cancelled("download stream receiver dropped".into()))
            }
        })
        .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Throwaway payment result — the assembler only moves it into the resume
    /// handle, never inspects it.
    fn dummy_batch_result() -> MerkleBatchPaymentResult {
        MerkleBatchPaymentResult {
            proofs: HashMap::new(),
            chunk_count: 0,
            storage_cost_atto: "0".into(),
            gas_cost_wei: 0,
            merkle_payment_timestamp: 0,
        }
    }

    fn empty_chunk_store() -> ExternalChunkStore {
        ExternalChunkStore::from_spill(ChunkSpill::new().unwrap())
    }

    /// A minimal already-paid chunk — the wave assembler only moves it and reads
    /// its `address`, so the body/proof/targets can be trivial.
    fn paid_chunk(address: [u8; 32]) -> PaidChunk {
        PaidChunk {
            content: Bytes::from_static(b"x"),
            address,
            quoted_peers: Vec::new(),
            proof_bytes: Vec::new(),
        }
    }

    #[test]
    fn assemble_complete_on_full_store() {
        let outcome = assemble_merkle_finalize_outcome(
            Ok((3, "0".into(), 0, WaveAggregateStats::default())),
            DataMap::new(vec![]),
            Some([9u8; 32]),
            3,
            empty_chunk_store(),
            dummy_batch_result(),
        )
        .expect("a fully-stored pass is not an error");
        match outcome {
            FinalizeOutcome::Complete(result) => {
                assert_eq!(result.chunks_stored, 3);
                assert_eq!(result.chunks_failed, 0);
                assert_eq!(result.total_chunks, 3);
                assert_eq!(result.data_map_address, Some([9u8; 32]));
                assert!(matches!(result.payment_mode_used, PaymentMode::Merkle));
            }
            FinalizeOutcome::Partial { .. } => panic!("expected Complete"),
        }
    }

    #[test]
    fn assemble_partial_retains_resume_for_unstored() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        // One chunk stored, two still short of quorum after retries.
        let store_result = Err(Error::PartialUpload {
            stored: vec![a],
            stored_count: 1,
            failed: vec![(b, "quorum".into()), (c, "quorum".into())],
            failed_count: 2,
            total_chunks: 3,
            spend: Box::new(PartialUploadSpend {
                storage_cost_atto: "777".into(),
                gas_cost_wei: 0,
            }),
            reason: "merkle chunk store aborted".into(),
        });
        let outcome = assemble_merkle_finalize_outcome(
            store_result,
            DataMap::new(vec![]),
            Some([9u8; 32]),
            3,
            empty_chunk_store(),
            dummy_batch_result(),
        )
        .expect("a quorum shortfall is Ok(Partial), never Err");
        match outcome {
            FinalizeOutcome::Partial { result, resume } => {
                // Snapshot reports real progress + spend from the payment.
                assert_eq!(result.chunks_stored, 1);
                assert_eq!(result.chunks_failed, 2);
                assert_eq!(result.total_chunks, 3);
                assert_eq!(result.storage_cost_atto, "777");
                let FinalizeResume::Merkle(m) = resume else {
                    panic!("expected a merkle resume handle");
                };
                // Resume targets exactly the unstored chunks, carries the stored
                // set forward as already-stored, and preserves public + total.
                assert_eq!(m.unstored_addresses, vec![b, c]);
                assert_eq!(m.stored_addresses, vec![a]);
                assert_eq!(m.total_chunks, 3);
                assert_eq!(m.data_map_address, Some([9u8; 32]));
            }
            FinalizeOutcome::Complete(_) => panic!("expected Partial"),
        }
    }

    #[test]
    fn resumable_guard_rejects_partial_payment() {
        // Regression for the PR #172 review: a Some/None mix must not reach the
        // resumable path — its resume handle could never acquire proofs for the
        // unpaid chunks, so repeated finalize_resume calls would return Partial
        // forever instead of draining to Complete.
        let err = require_fully_paid_for_resumable(&[Some([1u8; 32]), None, Some([2u8; 32])])
            .expect_err("a mix of paid and unpaid sub-batches must be rejected");
        match err {
            Error::Payment(msg) => {
                assert!(msg.contains("1/3"), "counts unpaid batches: {msg}");
                assert!(
                    msg.contains("finalize_upload_merkle_multi()"),
                    "points at the non-resumable path: {msg}"
                );
            }
            other => panic!("expected Error::Payment, got {other:?}"),
        }
    }

    #[test]
    fn resumable_guard_accepts_fully_paid() {
        require_fully_paid_for_resumable(&[Some([1u8; 32]), Some([2u8; 32])])
            .expect("fully-paid winner hashes pass the guard");
        require_fully_paid_for_resumable(&[]).expect(
            "an empty set has no unpaid batch — fold_external_merkle_payments \
             rejects it as nothing-to-finalize",
        );
    }

    #[test]
    fn merkle_resume_handle_drains_to_complete() {
        // Regression for the PR #172 review: drive the resume-handoff contract
        // through two passes and prove the handle drains. Pass 1 stores one of
        // three chunks; the Partial handle carries the unstored set plus the
        // original payment. Pass 2 re-drives exactly that handle's material and
        // stores the rest, reaching Complete with whole-file counts.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let first_pass = Err(Error::PartialUpload {
            stored: vec![a],
            stored_count: 1,
            failed: vec![(b, "quorum".into()), (c, "quorum".into())],
            failed_count: 2,
            total_chunks: 3,
            spend: Box::new(PartialUploadSpend {
                storage_cost_atto: "777".into(),
                gas_cost_wei: 0,
            }),
            reason: "quorum shortfall".into(),
        });
        let outcome = assemble_merkle_finalize_outcome(
            first_pass,
            DataMap::new(vec![]),
            Some([9u8; 32]),
            3,
            empty_chunk_store(),
            dummy_batch_result(),
        )
        .expect("a quorum shortfall is Ok(Partial), never Err");
        let FinalizeOutcome::Partial { resume, .. } = outcome else {
            panic!("expected Partial after a shortfall pass");
        };
        let FinalizeResume::Merkle(m) = resume else {
            panic!("expected a merkle resume handle");
        };
        assert_eq!(m.unstored_addresses, vec![b, c]);

        // Second pass: finalize_resume feeds the handle's own fields back into
        // the drive; simulate its store pass succeeding for the remainder.
        let second_pass = Ok((3, "0".into(), 0, WaveAggregateStats::default()));
        let outcome = assemble_merkle_finalize_outcome(
            second_pass,
            m.data_map,
            m.data_map_address,
            m.total_chunks,
            m.chunk_store,
            m.batch_result,
        )
        .expect("a fully-stored resume pass is not an error");
        match outcome {
            FinalizeOutcome::Complete(result) => {
                assert_eq!(result.chunks_stored, 3);
                assert_eq!(result.chunks_failed, 0);
                assert_eq!(result.total_chunks, 3);
                assert_eq!(result.data_map_address, Some([9u8; 32]));
            }
            FinalizeOutcome::Partial { .. } => panic!("expected Complete after the drain pass"),
        }
    }

    #[test]
    fn assemble_propagates_fatal_error() {
        // A non-recoverable error is not folded into a resumable outcome.
        let outcome = assemble_merkle_finalize_outcome(
            Err(Error::Payment("on-chain call reverted".into())),
            DataMap::new(vec![]),
            None,
            3,
            empty_chunk_store(),
            dummy_batch_result(),
        );
        assert!(matches!(outcome, Err(Error::Payment(_))));
    }

    #[test]
    fn assemble_wave_complete_when_all_stored() {
        let a = [1u8; 32];
        let wave_result = WaveResult {
            stored: vec![a],
            failed: Vec::new(),
            chunk_attempts_total: 1,
            store_durations_ms: vec![5],
            retries_per_chunk: vec![0],
        };
        let mut retained = HashMap::new();
        retained.insert(a, paid_chunk(a));
        let outcome = assemble_wave_finalize_outcome(
            wave_result,
            retained,
            Vec::new(),
            DataMap::new(vec![]),
            Some([9u8; 32]),
            1,
            0,
            "500".into(),
        );
        match outcome {
            FinalizeOutcome::Complete(result) => {
                assert_eq!(result.chunks_stored, 1);
                assert_eq!(result.chunks_failed, 0);
                assert_eq!(result.storage_cost_atto, "500");
                assert!(matches!(result.payment_mode_used, PaymentMode::Single));
            }
            FinalizeOutcome::Partial { .. } => panic!("expected Complete"),
        }
    }

    #[test]
    fn assemble_wave_partial_retains_failed_paid_chunks() {
        let a = [1u8; 32]; // stored
        let b = [2u8; 32]; // failed
        let c = [3u8; 32]; // failed
        let wave_result = WaveResult {
            stored: vec![a],
            failed: vec![(b, "quorum".into()), (c, "quorum".into())],
            chunk_attempts_total: 3,
            store_durations_ms: vec![5],
            retries_per_chunk: vec![0],
        };
        // All three were paid; only the two failures should be retained.
        let mut retained = HashMap::new();
        for addr in [a, b, c] {
            retained.insert(addr, paid_chunk(addr));
        }
        let outcome = assemble_wave_finalize_outcome(
            wave_result,
            retained,
            Vec::new(),
            DataMap::new(vec![]),
            Some([9u8; 32]),
            3,
            0,
            "500".into(),
        );
        match outcome {
            FinalizeOutcome::Partial { result, resume } => {
                assert_eq!(result.chunks_stored, 1);
                assert_eq!(result.chunks_failed, 2);
                assert_eq!(result.storage_cost_atto, "500");
                let FinalizeResume::Wave(w) = resume else {
                    panic!("expected a wave resume handle");
                };
                // Exactly the two failed chunks are kept for re-store — no re-pay.
                let mut got: Vec<[u8; 32]> =
                    w.failed_paid_chunks.iter().map(|pc| pc.address).collect();
                got.sort();
                assert_eq!(got, vec![b, c]);
                assert_eq!(w.stored_count, 1);
                assert_eq!(w.total_chunks, 3);
                assert!(w.occupied().is_empty());
            }
            FinalizeOutcome::Complete(_) => panic!("expected Partial"),
        }
    }

    /// A chunk whose paid quote was occupied can't be stored on this payment:
    /// it is counted failed, its paid chunk is not in the resume handle, and
    /// the handle lists it, so every pass reports it failed again and none
    /// completes the upload.
    #[test]
    fn an_occupied_chunk_stays_failed_and_out_of_the_resume_handle() {
        let a = [1u8; 32]; // stored
        let b = [2u8; 32]; // occupied
        let e = [7u8; 32]; // the envelope, held back
        let occupied = vec![(b, "payment error: quotes occupied: …".to_string())];
        let wave_result = WaveResult {
            stored: vec![a],
            failed: vec![
                occupied[0].clone(),
                (e, crate::data::client::upload::HELD_BACK.into()),
            ],
            chunk_attempts_total: 1,
            store_durations_ms: vec![5],
            retries_per_chunk: vec![0],
        };
        // The occupied chunk was set aside before storing: never retained.
        let mut retained = HashMap::new();
        for addr in [a, e] {
            retained.insert(addr, paid_chunk(addr));
        }
        let outcome = assemble_wave_finalize_outcome(
            wave_result,
            retained,
            occupied.clone(),
            DataMap::new(vec![]),
            None,
            3,
            0,
            "450".into(),
        );
        let FinalizeOutcome::Partial { result, resume } = outcome else {
            panic!("an occupied chunk never completes the upload");
        };
        assert_eq!(result.chunks_failed, 2);
        assert_eq!(result.storage_cost_atto, "450");
        let FinalizeResume::Wave(w) = resume else {
            panic!("expected a wave resume handle");
        };
        let kept: Vec<[u8; 32]> = w.failed_paid_chunks.iter().map(|c| c.address).collect();
        assert_eq!(kept, vec![e], "only the held-back envelope is kept");
        assert_eq!(w.occupied(), occupied.as_slice());
        assert!(format!("{w:?}").contains("occupied: 1"), "{w:?}");
    }

    /// Chunks set aside before storing count as failed for the envelope: it
    /// is held back, not sent, and they are reported first, with their own
    /// reasons. The client's node was never started, so the envelope could
    /// only have been held back.
    #[tokio::test]
    async fn chunks_set_aside_hold_the_envelope_back() {
        let network = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(Arc::clone(network.node()), Default::default());
        let occupied = [2u8; 32];
        let envelope = [7u8; 32];
        let reason = "payment error: quotes occupied: …".to_string();
        let result = client
            .store_paid_chunks_then(
                vec![paid_chunk(envelope)],
                Some(envelope),
                vec![(occupied, reason.clone())],
                None,
                0,
                3,
            )
            .await;
        assert!(result.stored.is_empty());
        assert_eq!(
            result.failed,
            vec![
                (occupied, reason),
                (envelope, crate::data::client::upload::HELD_BACK.into())
            ]
        );
        assert_eq!(result.chunk_attempts_total, 0, "nothing was sent");
    }

    #[test]
    fn merkle_store_cap_clamps_to_memory_bound() {
        // Below the ceiling: pass the adaptive cap through unchanged.
        assert_eq!(merkle_store_cap(8), 8);
        assert_eq!(merkle_store_cap(64), 64);
        // A configured `adaptive.max.store` above the ceiling must be clamped so
        // the whole-file fan-out can't pin more than ~256 MB of bodies (PR #137).
        assert_eq!(merkle_store_cap(512), MERKLE_STORE_MAX_IN_FLIGHT);
        assert_eq!(merkle_store_cap(usize::MAX), MERKLE_STORE_MAX_IN_FLIGHT);
        // Never zero — always make progress.
        assert_eq!(merkle_store_cap(0), 1);
    }

    #[test]
    fn distributed_sample_indices_spreads_across_large_file() {
        // cap 5 over 100 chunks: first and last included, evenly spread.
        assert_eq!(distributed_sample_indices(100, 5), vec![0, 24, 49, 74, 99]);
    }

    #[test]
    fn distributed_sample_indices_covers_whole_small_file() {
        // total <= cap returns every index, preserving the exact
        // "whole file sampled" detection in estimate_upload_cost.
        assert_eq!(distributed_sample_indices(3, 5), vec![0, 1, 2]);
        assert_eq!(distributed_sample_indices(5, 5), vec![0, 1, 2, 3, 4]);
    }

    /// The estimator bills what the upload engine pays: each batch's padded
    /// tree plus the remainder paid per chunk, from the same split.
    #[test]
    fn estimator_units_are_the_upload_engine_split() {
        for chunks in [
            2u64, 9, 31, 32, 64, 65, 100, 129, 130, 255, 256, 257, 300, 512, 513, 769,
        ] {
            let split = merkle_upload_split(chunks as usize, chunks as usize);
            let leaves: u64 = split
                .batches
                .iter()
                .map(|size| size.next_power_of_two() as u64)
                .sum();
            assert_eq!(
                merkle_upload_billable_units(chunks),
                leaves + split.per_chunk as u64,
                "{chunks} chunks must be billed for the split the upload engine pays"
            );
        }
    }

    #[test]
    fn distributed_sample_indices_is_in_range_and_increasing() {
        assert!(distributed_sample_indices(0, 5).is_empty());
        assert_eq!(distributed_sample_indices(1, 5), vec![0]);
        for total in 1..200usize {
            let idx = distributed_sample_indices(total, 5);
            assert_eq!(*idx.first().unwrap(), 0);
            assert_eq!(*idx.last().unwrap(), total - 1);
            assert!(idx.iter().all(|&i| i < total));
            assert!(idx.windows(2).all(|w| w[0] < w[1]));
        }
    }

    #[test]
    fn disk_space_check_passes_for_small_file() {
        // A 1 KB file should always pass the disk space check
        check_disk_space_for_spill(1024).unwrap();
    }

    #[test]
    fn disk_space_check_fails_for_absurd_size() {
        // Requesting space for a 1 exabyte file should fail on any real system
        let result = check_disk_space_for_spill(u64::MAX / 2);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::InsufficientDiskSpace(_)),
            "expected InsufficientDiskSpace, got: {err}"
        );
    }

    /// External multi-batch payment fold: winner-hash validation and
    /// paid/unpaid mixes (ADR-0003).
    mod external_merkle_fold {
        use super::*;
        use crate::data::client::merkle::test_support::{
            make_prepared_merkle_batch, winner_hash_for,
        };

        #[test]
        fn hash_count_mismatch_is_rejected() {
            let batches = vec![make_prepared_merkle_batch(2), make_prepared_merkle_batch(3)];
            let err = fold_external_merkle_payments(batches, vec![None]).unwrap_err();
            assert!(
                err.to_string().contains("winner pool hash entries"),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn all_unpaid_is_rejected() {
            let batches = vec![make_prepared_merkle_batch(2)];
            let err = fold_external_merkle_payments(batches, vec![None]).unwrap_err();
            assert!(
                err.to_string().contains("No merkle sub-batch was paid"),
                "unexpected error: {err}"
            );
        }

        /// A k-of-N payment makes forward progress: the paid batch's proofs
        /// fold in, the unpaid batch contributes none — so the store phase
        /// reports its chunks via `PartialUpload` instead of aborting.
        #[test]
        fn paid_batches_fold_and_unpaid_contribute_no_proofs() {
            let paid = make_prepared_merkle_batch(2);
            let unpaid = make_prepared_merkle_batch(3);
            let winner = winner_hash_for(&paid);
            let merged =
                fold_external_merkle_payments(vec![paid, unpaid], vec![Some(winner), None])
                    .unwrap();
            assert_eq!(merged.proofs.len(), 2, "proofs cover only the paid batch");
            assert_eq!(merged.chunk_count, 2);
        }
    }

    #[test]
    fn adaptive_stream_decrypt_batch_size_tracks_fetch_headroom() {
        let batch_size = adaptive_stream_decrypt_batch_size(1_000, 64, 10, Some(u64::MAX));

        assert_eq!(batch_size, 64 * DOWNLOAD_STREAM_BATCH_FETCH_MULTIPLIER);
    }

    #[test]
    fn adaptive_stream_decrypt_batch_size_caps_to_total_chunks() {
        let batch_size = adaptive_stream_decrypt_batch_size(12, 64, 10, Some(u64::MAX));

        assert_eq!(batch_size, 12);
    }

    #[test]
    fn adaptive_stream_decrypt_batch_size_honours_configured_floor() {
        let batch_size = adaptive_stream_decrypt_batch_size(1_000, 1, 32, None);

        assert_eq!(batch_size, 32);
    }

    #[test]
    fn adaptive_stream_decrypt_batch_size_does_not_expand_without_memory_reading() {
        let batch_size = adaptive_stream_decrypt_batch_size(1_000, 64, 10, None);

        assert_eq!(batch_size, 10);
    }

    #[test]
    fn adaptive_stream_decrypt_batch_size_caps_to_memory_budget() {
        let estimated_bytes_per_chunk = (self_encryption::MAX_CHUNK_SIZE as u64)
            .saturating_mul(DOWNLOAD_STREAM_BATCH_BYTES_PER_CHUNK_MULTIPLIER)
            .max(1);
        let usable_memory = estimated_bytes_per_chunk
            .saturating_mul(16)
            .saturating_mul(DOWNLOAD_STREAM_BATCH_MEMORY_BUDGET_DIVISOR);
        let batch_size = adaptive_stream_decrypt_batch_size(1_000, 256, 10, Some(usable_memory));

        assert_eq!(batch_size, 16);
    }

    #[test]
    fn adaptive_stream_decrypt_batch_size_keeps_one_chunk_when_memory_is_tight() {
        let batch_size = adaptive_stream_decrypt_batch_size(1_000, 64, 10, Some(1));

        assert_eq!(batch_size, 1);
    }

    #[test]
    fn cached_merkle_covers_only_when_all_addresses_have_proofs() {
        let covered = compute_address(&Bytes::from_static(b"covered"));
        let extra = compute_address(&Bytes::from_static(b"extra"));
        let missing = compute_address(&Bytes::from_static(b"missing"));
        let cached = MerkleBatchPaymentResult {
            proofs: HashMap::from([(covered, vec![1]), (extra, vec![2])]),
            chunk_count: 2,
            storage_cost_atto: "0".to_string(),
            gas_cost_wei: 0,
            merkle_payment_timestamp: 0,
        };

        assert!(cached_merkle_covers_addresses(&cached, &[covered]));
        assert!(cached_merkle_covers_addresses(&cached, &[covered, extra]));
        assert!(!cached_merkle_covers_addresses(
            &cached,
            &[covered, missing]
        ));
    }

    /// A partial merkle payment leaves some addresses without a proof. Those
    /// must be split out so `upload_merkle_from_spill` reports them as failed
    /// (`PartialUpload`) instead of aborting the whole file — preserving the
    /// addresses' original order in each group.
    #[test]
    fn partition_addresses_by_proof_splits_paid_and_unpaid() {
        let paid_a = [1u8; 32];
        let unpaid_b = [2u8; 32];
        let paid_c = [3u8; 32];
        let unpaid_d = [4u8; 32];
        let proofs: HashMap<[u8; 32], Vec<u8>> =
            HashMap::from([(paid_a, vec![0xaa]), (paid_c, vec![0xcc])]);

        let (to_store, missing) =
            partition_addresses_by_proof(&[paid_a, unpaid_b, paid_c, unpaid_d], &proofs);

        assert_eq!(to_store, vec![paid_a, paid_c]);
        assert_eq!(missing, vec![unpaid_b, unpaid_d]);
    }

    /// The real storer wording, as `ant_protocol::client_update_required_message`
    /// builds it. Used verbatim so the tests exercise the "nothing was charged"
    /// clause that has to be scoped before it is quoted.
    fn real_refusal() -> String {
        ant_protocol::client_update_required_message(1, 2)
    }

    /// The defect: a multi-batch merkle payment stops when storers refuse this
    /// client's settlement version, and the chunks its later sub-batches never
    /// covered reach the store path with no proof. The CLI prints this reason
    /// and nothing else, so calling them short of quorum after N attempts
    /// reports a failure they never had and drops the storer's upgrade
    /// instruction, which is the only thing that makes the next attempt work.
    #[test]
    fn the_partial_reason_carries_a_refusal_instead_of_a_bogus_shortfall() {
        let refusal = real_refusal();
        assert!(
            refusal.contains("ant update"),
            "the storer wording must carry the instruction: {refusal}"
        );

        // Every failed chunk is one the payment never covered.
        let all_proofless = merkle_partial_reason(3, 3, 4, Some(&refusal));
        assert!(all_proofless.contains("ant update"), "{all_proofless}");
        assert!(
            !all_proofless.contains("short of quorum"),
            "{all_proofless}"
        );

        // Mixed: two with no proof, one genuinely short of quorum. Both halves
        // survive and the counts still add up to the three that failed.
        let mixed = merkle_partial_reason(3, 2, 4, Some(&refusal));
        assert!(mixed.contains("ant update"), "{mixed}");
        assert!(mixed.contains("2 chunk(s) have no merkle proof"), "{mixed}");
        assert!(
            mixed.contains("1 chunk(s) short of quorum after 4 attempts"),
            "{mixed}"
        );

        // No refusal: still not a quorum shortfall, just no proof.
        let silent = merkle_partial_reason(2, 2, 4, None);
        assert!(!silent.contains("short of quorum"), "{silent}");
        assert!(
            silent.contains("2 chunk(s) have no merkle proof"),
            "{silent}"
        );
        assert!(!silent.contains("refused"), "{silent}");
    }

    /// The storer's wording says nothing was charged. That is true of the
    /// sub-batch it refused and false of the upload, whose earlier sub-batches
    /// settled — and the CLI prints that spend on the same line. Quoting it
    /// unscoped would read as "spent X ... nothing was charged".
    #[test]
    fn the_refusal_is_scoped_before_its_nothing_was_charged_clause_is_quoted() {
        let refusal = real_refusal();
        assert!(
            refusal.contains("nothing was charged"),
            "precondition: {refusal}"
        );

        let reason = merkle_partial_reason(2, 2, 4, Some(&refusal));

        // The scope has to come BEFORE the quoted refusal, or the reader hits
        // "nothing was charged" with no qualification.
        let scope = reason
            .find("settled for earlier sub-batches")
            .expect("the reason must scope the refusal");
        let charged = reason
            .find("nothing was charged")
            .expect("the storer wording must still be quoted in full");
        assert!(scope < charged, "scope must precede the claim: {reason}");
    }

    /// The ordinary case — every chunk had a proof and simply could not reach
    /// quorum — must read exactly as it did before.
    #[test]
    fn the_partial_reason_is_unchanged_when_every_chunk_had_a_proof() {
        assert_eq!(
            merkle_partial_reason(2, 0, 4, None),
            "2 chunk(s) short of quorum after 4 attempts"
        );
        // A refusal is irrelevant when nothing is missing a proof: the
        // failures really are quorum shortfalls.
        assert_eq!(
            merkle_partial_reason(2, 0, 4, Some(&real_refusal())),
            "2 chunk(s) short of quorum after 4 attempts"
        );
    }

    /// A sub-batch settles on-chain BEFORE its proofs are generated, so a
    /// proof-generation failure leaves chunks that were charged for and have
    /// no proof. The wording must never claim a proof-less chunk went unpaid,
    /// or it tells the user their money is safe when it is not.
    #[test]
    fn the_reason_never_claims_a_proofless_chunk_went_unpaid() {
        // The clause the store path contributes, with no storer wording mixed
        // in, so this asserts on our own words only.
        let ours = proofless_clause(2, None).expect("two proofless chunks produce a clause");
        assert_eq!(ours, "2 chunk(s) have no merkle proof");
        assert!(!ours.contains("paid"), "{ours}");
        assert!(!ours.contains("charged"), "{ours}");

        assert!(proofless_clause(0, None).is_none());
        assert!(
            proofless_clause(0, Some(&real_refusal())).is_none(),
            "no proofless chunks means no clause, refusal or not"
        );
    }

    /// A store abort and a refusal that stopped the payment are independent
    /// failures with different remedies. The abort is the immediate cause and
    /// leads, but dropping the other leaves its remedy only in the per-chunk
    /// messages, which the CLI does not print.
    #[test]
    fn a_fatal_store_abort_still_reports_the_refusal() {
        let abort = "merkle chunk store aborted: connection reset";
        let refusal = real_refusal();

        let both = merkle_fatal_reason(abort, 5, Some(&refusal));
        assert!(both.starts_with(abort), "the abort leads: {both}");
        assert!(both.contains("ant update"), "{both}");
        assert!(both.contains("5 chunk(s) have no merkle proof"), "{both}");

        // Every chunk had a proof, so there is nothing to add.
        assert_eq!(merkle_fatal_reason(abort, 0, Some(&refusal)), abort);
        assert_eq!(merkle_fatal_reason(abort, 0, None), abort);
    }

    /// A wave that returns `Ok` contributes its stored chunks, parsed cost, and
    /// stats; nothing is recorded as failed.
    #[test]
    fn fold_single_wave_keeps_ok_wave() {
        let stored = vec![[1u8; 32], [2u8; 32]];
        let stats = WaveAggregateStats {
            chunk_attempts_total: 7,
            ..Default::default()
        };

        let outcome = fold_single_wave(Ok((stored.clone(), "100".to_string(), 9, stats))).unwrap();

        assert_eq!(outcome.stored, stored);
        assert!(outcome.failed.is_empty());
        assert_eq!(outcome.storage_atto.to_string(), "100");
        assert_eq!(outcome.gas_wei, 9);
        assert_eq!(outcome.stats.chunk_attempts_total, 7);
    }

    /// The core V2-461 semantic: a wave short of quorum (`PartialUpload`) is
    /// recoverable — its stored chunks, failed chunks, and on-chain spend are
    /// folded so the caller can continue to the next wave rather than aborting
    /// the whole file.
    #[test]
    fn fold_single_wave_folds_partial_upload() {
        let stored = vec![[3u8; 32]];
        let failed = vec![([4u8; 32], "short of quorum".to_string())];
        let err = Error::PartialUpload {
            stored: stored.clone(),
            stored_count: 1,
            failed: failed.clone(),
            failed_count: 1,
            total_chunks: 2,
            spend: Box::new(PartialUploadSpend {
                storage_cost_atto: "250".to_string(),
                gas_cost_wei: 11,
            }),
            reason: "wave store failed after retries".to_string(),
        };

        let outcome = fold_single_wave(Err(err)).unwrap();

        assert_eq!(outcome.stored, stored);
        assert_eq!(outcome.failed, failed);
        assert_eq!(outcome.storage_atto.to_string(), "250");
        assert_eq!(outcome.gas_wei, 11);
        // `PartialUpload` carries no stats, so the failed wave contributes none.
        assert_eq!(outcome.stats.chunk_attempts_total, 0);
    }

    /// A non-`PartialUpload` error (wallet/payment-infrastructure failure) is
    /// fatal and must abort the file, not be folded into the failed set.
    #[test]
    fn fold_single_wave_propagates_fatal_error() {
        let result = fold_single_wave(Err(Error::Payment("wallet unavailable".to_string())));

        assert!(
            matches!(result, Err(Error::Payment(_))),
            "fatal payment error must propagate, got: {result:?}"
        );
    }

    /// A merkle store pass over `count` spilled chunks, `with_proofs` of them
    /// given a proof, after `already_stored`, on a client whose node was never
    /// started: so nothing reaches a node.
    async fn merkle_pass_without_nodes(
        count: u8,
        with_proofs: usize,
        already_stored: &[[u8; 32]],
    ) -> (Vec<[u8; 32]>, Error) {
        let network = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(Arc::clone(network.node()), Default::default());
        let mut spill = ChunkSpill::new().unwrap();
        for i in 0..count {
            spill.push(&[i; 1024]).unwrap();
        }
        let addresses = spill.addresses.clone();
        let batch = MerkleBatchPaymentResult {
            proofs: addresses
                .iter()
                .take(with_proofs)
                .map(|address| (*address, vec![0xcc]))
                .collect(),
            chunk_count: with_proofs,
            storage_cost_atto: "640".into(),
            gas_cost_wei: 21,
            merkle_payment_timestamp: 0,
        };
        let error = client
            .upload_merkle_from_spill(&spill, &addresses, &batch, already_stored, None, None)
            .await
            .expect_err("a chunk not stored leaves the upload partial");
        (addresses, error)
    }

    /// What the end-to-end test of an external signer paying one of two
    /// merkle sub-batches checked of the accounting, which no node can reach
    /// now that darwin-node refuses batch payments: the chunks no paid
    /// sub-batch gave a proof are reported failed, each as missing its proof,
    /// beside those already stored, the counts cover the file, the spend is
    /// the batch's, and the reason calls them proofless, not short of
    /// quorum, with no refusal.
    #[tokio::test]
    async fn chunks_with_no_merkle_proof_are_reported_beside_those_stored() {
        let stored = [[0xaa; 32], [0xbb; 32]];
        let (proofless, error) = merkle_pass_without_nodes(3, 0, &stored).await;
        let Error::PartialUpload {
            stored: stored_now,
            stored_count,
            failed,
            failed_count,
            total_chunks,
            spend,
            reason,
        } = error
        else {
            panic!("expected PartialUpload, got: {error:?}");
        };
        assert_eq!(stored_now, stored.to_vec());
        assert_eq!(stored_count, 2);
        assert_eq!(failed_count, 3);
        assert_eq!(total_chunks, 5);
        let mut failed_addresses: Vec<[u8; 32]> = failed.iter().map(|(a, _)| *a).collect();
        failed_addresses.sort_unstable();
        let mut expected = proofless.clone();
        expected.sort_unstable();
        assert_eq!(failed_addresses, expected);
        for (address, message) in &failed {
            assert_eq!(
                message,
                &format!("Missing merkle proof for chunk {}", hex::encode(address))
            );
        }
        assert_eq!(reason, "3 chunk(s) have no merkle proof");
        assert!(!reason.contains("short of quorum"), "{reason}");
        assert!(
            !reason.contains("refused") && !reason.contains("update"),
            "{reason}"
        );
        assert_eq!(spend.storage_cost_atto, "640");
        assert_eq!(spend.gas_cost_wei, 21);
    }

    /// With proofs for some chunks only, those are sent: finding no node,
    /// they are short of quorum through every deferred round (the paused
    /// clock skips the rounds' waits) and fail with that, while the rest keep
    /// their own reason. The counts cover the file, nothing is counted stored
    /// that wasn't, and the reason gives both groups.
    #[tokio::test(start_paused = true)]
    async fn chunks_with_and_without_merkle_proofs_are_all_accounted_for() {
        let stored = [[0xaa; 32]];
        let (addresses, error) = merkle_pass_without_nodes(4, 2, &stored).await;
        let Error::PartialUpload {
            stored: stored_now,
            stored_count,
            failed,
            failed_count,
            total_chunks,
            reason,
            ..
        } = error
        else {
            panic!("expected PartialUpload, got: {error:?}");
        };
        assert_eq!(stored_now, stored.to_vec());
        assert_eq!(stored_count, 1);
        assert_eq!(failed_count, 4);
        assert_eq!(failed.len(), failed_count);
        assert_eq!(stored_count + failed_count, total_chunks);
        assert_eq!(total_chunks, 5);
        let messages: HashMap<[u8; 32], String> = failed.into_iter().collect();
        assert_eq!(messages.len(), 4, "each chunk is reported once");
        for (i, address) in addresses.iter().enumerate() {
            let message = &messages[address];
            let proofless = format!("Missing merkle proof for chunk {}", hex::encode(address));
            if i < 2 {
                assert_ne!(message, &proofless, "it had a proof");
            } else {
                assert_eq!(message, &proofless);
            }
        }
        assert_eq!(
            reason,
            format!(
                "2 chunk(s) short of quorum after {} attempts; 2 chunk(s) have no merkle proof",
                1 + DEFERRED_ROUND_DELAYS_SECS.len()
            )
        );
    }

    /// A settlement refusal on a later wave must not be reported as if nothing
    /// was charged: the earlier waves paid before storing. The refusal is
    /// reshaped into a `PartialUpload` that carries the real spend, the stored
    /// set (for resume), every un-quoted chunk as failed, and the storer's
    /// upgrade instruction in the reason.
    #[test]
    fn settlement_refusal_after_paid_waves_carries_spend_and_upgrade_instruction() {
        let refusal = &crate::data::client::quote::update_required_message(1, 2);
        let stored = vec![[1u8; 32], [2u8; 32]];
        let remaining = [[3u8; 32], [4u8; 32], [5u8; 32]];

        let err = settlement_refusal_after_paid_waves(
            refusal,
            2,
            3,
            stored.clone(),
            stored.len(),
            &remaining,
            5,
            Amount::from(700u64),
            13,
        );

        let Error::PartialUpload {
            stored: got_stored,
            stored_count,
            failed,
            failed_count,
            total_chunks,
            spend,
            reason,
        } = err
        else {
            panic!("expected PartialUpload, got: {err:?}");
        };
        assert_eq!(got_stored, stored);
        assert_eq!(stored_count, 2);
        assert_eq!(failed_count, 3);
        assert_eq!(total_chunks, 5);
        // Every un-quoted chunk is listed, none of them as "stored".
        let failed_addrs: Vec<[u8; 32]> = failed.iter().map(|(a, _)| *a).collect();
        assert_eq!(failed_addrs, remaining.to_vec());
        assert!(failed.iter().all(|(_, why)| why.contains("not quoted")));
        // The spend is what the earlier waves actually paid, not zero.
        assert_eq!(spend.storage_cost_atto, "700");
        assert_eq!(spend.gas_cost_wei, 13);
        // The user learns both facts: earlier waves paid, and how to upgrade.
        assert!(reason.contains("wave 2/3"), "reason: {reason}");
        assert!(
            reason.contains("2 chunk(s) in earlier wave(s) were already paid"),
            "reason: {reason}"
        );
        assert!(
            reason.contains("3 chunk(s) were neither quoted nor paid"),
            "reason: {reason}"
        );
        assert!(reason.contains(refusal), "reason: {reason}");
    }

    #[test]
    fn partition_addresses_by_proof_handles_all_or_nothing() {
        let a = [5u8; 32];
        let b = [6u8; 32];

        // No proofs at all → every address is missing.
        let empty: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let (to_store, missing) = partition_addresses_by_proof(&[a, b], &empty);
        assert!(to_store.is_empty());
        assert_eq!(missing, vec![a, b]);

        // All proofs present → nothing missing.
        let full: HashMap<[u8; 32], Vec<u8>> = HashMap::from([(a, vec![1]), (b, vec![2])]);
        let (to_store, missing) = partition_addresses_by_proof(&[a, b], &full);
        assert_eq!(to_store, vec![a, b]);
        assert!(missing.is_empty());
    }

    #[test]
    fn chunk_spill_round_trip() {
        let mut spill = ChunkSpill::new().unwrap();
        let data1 = vec![0xAA; 1024];
        let data2 = vec![0xBB; 2048];

        spill.push(&data1).unwrap();
        spill.push(&data2).unwrap();

        assert_eq!(spill.len(), 2);
        assert_eq!(spill.total_bytes(), 1024 + 2048);
        let chunk_entries = spill.chunk_entries().unwrap();
        let entry_total: u64 = chunk_entries.iter().map(|(_, size)| *size).sum();
        assert_eq!(entry_total, 1024 + 2048);

        // Read back and verify
        let chunk1 = spill.read_chunk(spill.addresses.first().unwrap()).unwrap();
        assert_eq!(&chunk1[..], &data1[..]);

        let chunk2 = spill.read_chunk(spill.addresses.get(1).unwrap()).unwrap();
        assert_eq!(&chunk2[..], &data2[..]);

        // Verify waves with 1-chunk wave size
        let waves: Vec<_> = spill.addresses.chunks(1).collect();
        assert_eq!(waves.len(), 2);
    }

    #[test]
    fn chunk_spill_cleanup_on_drop() {
        let dir;
        {
            let spill = ChunkSpill::new().unwrap();
            dir = spill.dir.clone();
            assert!(dir.exists());
        }
        // After drop, the directory should be cleaned up
        assert!(!dir.exists(), "spill dir should be removed on drop");
    }

    /// A record for `envelope`, as an upload builds it: the proof's fields
    /// don't need to check out to be kept and read back.
    fn record_for(envelope: &UploadEnvelope, map: &DataMap) -> ant_listings::EnvelopeProof {
        ant_listings::EnvelopeProof {
            address: envelope.address(),
            envelope: envelope.envelope.to_bytes(),
            tx_hash: [0xab; 32],
            quote: vec![1, 2, 3],
            data_map: envelope
                .salt
                .map(|_| ant_listings::encode_data_map(map).unwrap()),
            salt: envelope.salt,
        }
    }

    fn private_envelope(fill: u8, salt: ant_listings::Salt) -> (UploadEnvelope, DataMap) {
        let (map, _) = self_encryption::encrypt(Bytes::from(vec![fill; 4000])).unwrap();
        let (envelope, _) =
            build_upload_envelope(&EnvelopeOptions::private(), &map, Some(salt)).unwrap();
        (envelope, map)
    }

    /// Under a folder so deep that a kept record's path is longer than
    /// Windows' MAX_PATH (260 characters), a completed upload still keeps
    /// its record and removes its checkpoint, once the folder is
    /// [`long_path_safe`], as [`open_upload_checkpoint`] makes it.
    #[cfg(windows)]
    #[test]
    fn a_long_data_directory_still_keeps_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("d".repeat(120)).join("e".repeat(100));
        std::fs::create_dir_all(&deep).unwrap();
        let deep = long_path_safe(deep);
        assert!(deep.to_string_lossy().starts_with(r"\\?\"), "{deep:?}");
        let checkpoint = deep.join("upload.msgpack");
        let salt = upload_salt(&checkpoint).unwrap();
        std::fs::write(&checkpoint, b"state").unwrap();
        let (mut envelope, map) = private_envelope(5, salt);
        let record = record_for(&envelope, &map);
        envelope.proof = Some(record.clone());
        let payer = b"wallet one";
        let kept = kept_path(&deep, &envelope.address(), payer, "record");
        assert!(kept.as_os_str().len() > 264, "{}", kept.display());

        finish_upload_checkpoint(&checkpoint, Some(&envelope), payer);
        assert!(!checkpoint.exists(), "the checkpoint is removed");
        assert!(!checkpoint.with_extension("salt").exists());
        assert_eq!(
            kept_upload_record(&deep, &envelope, payer),
            Some(record),
            "the record is kept"
        );
        forget_kept(&deep, &envelope.address()).unwrap();
        assert_eq!(kept_upload_record(&deep, &envelope, payer), None);
    }

    #[test]
    fn a_completed_upload_keeps_its_record_until_the_caller_saves_it() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("upload.msgpack");
        let salt = upload_salt(&checkpoint).unwrap();
        assert!(checkpoint.with_extension("salt").exists());
        // An interrupted upload resumes with the same salt, so the same
        // envelope and the payment already made for it.
        assert_eq!(upload_salt(&checkpoint).unwrap(), salt);
        std::fs::write(&checkpoint, b"state").unwrap();
        let (mut envelope, map) = private_envelope(5, salt);
        let record = record_for(&envelope, &map);
        envelope.proof = Some(record.clone());
        let payer = b"wallet one";
        finish_upload_checkpoint(&checkpoint, Some(&envelope), payer);
        assert!(!checkpoint.exists());
        assert!(!checkpoint.with_extension("salt").exists());
        // The whole record survives the upload, by envelope address and
        // payer, as a record file: paid quote and tx hash included.
        let kept = kept_path(dir.path(), &envelope.address(), payer, "record");
        assert_eq!(crate::datamap_file::read_record(&kept).unwrap(), record);
        assert!(!kept_path(dir.path(), &envelope.address(), payer, "salt").exists());
        // Only the same payer gets it back, and only for this envelope.
        assert_eq!(
            kept_upload_record(dir.path(), &envelope, payer),
            Some(record.clone())
        );
        assert_eq!(
            kept_upload_record(dir.path(), &envelope, b"wallet two"),
            None
        );
        let (other, _) = private_envelope(6, salt);
        assert_eq!(kept_upload_record(dir.path(), &other, payer), None);
        // A completed upload's next one gets a new salt: the kept one is
        // never reused.
        assert_ne!(upload_salt(&checkpoint).unwrap(), salt);
        // Once the caller has saved it, it goes.
        forget_kept(dir.path(), &envelope.address()).unwrap();
        assert!(!kept.exists());
        assert_eq!(kept_upload_record(dir.path(), &envelope, payer), None);
        // Forgetting what isn't there is fine.
        forget_kept(dir.path(), &envelope.address()).unwrap();
        forget_kept(&dir.path().join("nowhere"), &envelope.address()).unwrap();

        // A damaged salt is replaced rather than used.
        std::fs::write(checkpoint.with_extension("salt"), b"short").unwrap();
        let replaced = upload_salt(&checkpoint).unwrap();
        assert_eq!(
            std::fs::read(checkpoint.with_extension("salt")).unwrap(),
            replaced.to_vec()
        );
    }

    #[test]
    fn without_a_record_a_private_upload_keeps_its_salt_and_a_readable_one_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let payer = b"payer";
        // A private envelope this upload didn't pay for: its salt is kept.
        let checkpoint = dir.path().join("private.msgpack");
        let salt = upload_salt(&checkpoint).unwrap();
        std::fs::write(&checkpoint, b"state").unwrap();
        let (envelope, _) = private_envelope(7, salt);
        finish_upload_checkpoint(&checkpoint, Some(&envelope), payer);
        assert!(!checkpoint.exists());
        let kept = kept_path(dir.path(), &envelope.address(), payer, "salt");
        assert_eq!(std::fs::read(&kept).unwrap(), salt.to_vec());
        assert_eq!(kept_upload_record(dir.path(), &envelope, payer), None);
        forget_kept(dir.path(), &envelope.address()).unwrap();
        assert!(!kept.exists());

        // A readable envelope keeps its record, or nothing without one.
        let (map, _) = self_encryption::encrypt(Bytes::from(vec![8u8; 4000])).unwrap();
        let (mut readable, _) =
            build_upload_envelope(&EnvelopeOptions::unlisted(), &map, None).unwrap();
        let checkpoint = dir.path().join("readable.msgpack");
        std::fs::write(&checkpoint, b"state").unwrap();
        finish_upload_checkpoint(&checkpoint, Some(&readable), payer);
        assert!(!checkpoint.exists());
        assert_eq!(
            std::fs::read_dir(dir.path().join("records"))
                .unwrap()
                .count(),
            0
        );
        readable.proof = Some(record_for(&readable, &map));
        std::fs::write(&checkpoint, b"state").unwrap();
        finish_upload_checkpoint(&checkpoint, Some(&readable), payer);
        assert_eq!(
            kept_upload_record(dir.path(), &readable, payer),
            readable.proof.clone()
        );
        forget_kept(dir.path(), &readable.address()).unwrap();
        assert_eq!(kept_upload_record(dir.path(), &readable, payer), None);
    }

    #[cfg(unix)]
    #[test]
    fn salts_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let owner_only = |path: &Path| {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{} is {mode:o}", path.display());
        };
        let dir = tempfile::tempdir().unwrap();
        let payer = b"payer";
        // The salt saved next to the checkpoint, then the one kept for a
        // private envelope without a record once the upload completes.
        let checkpoint = dir.path().join("private.msgpack");
        let salt = upload_salt(&checkpoint).unwrap();
        owner_only(&checkpoint.with_extension("salt"));
        std::fs::write(&checkpoint, b"state").unwrap();
        let (envelope, _) = private_envelope(7, salt);
        finish_upload_checkpoint(&checkpoint, Some(&envelope), payer);
        owner_only(&kept_path(dir.path(), &envelope.address(), payer, "salt"));
    }

    #[test]
    fn finishing_a_checkpoint_never_fails_a_completed_upload() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing to remove: fine.
        finish_upload_checkpoint(&dir.path().join("gone.msgpack"), None, b"");
        // A checkpoint that can't be removed (here a directory) is only
        // logged, and an upload without an envelope keeps nothing.
        let checkpoint = dir.path().join("stuck.msgpack");
        std::fs::create_dir(&checkpoint).unwrap();
        finish_upload_checkpoint(&checkpoint, None, b"");
        assert!(checkpoint.exists());
        assert!(!dir.path().join("records").exists());
        // If the record can't be kept (here `records` is a file), the
        // checkpoint and its salt both stay, so the next upload of the same
        // file resumes and builds the record again.
        let checkpoint = dir.path().join("upload.msgpack");
        let salt = upload_salt(&checkpoint).unwrap();
        std::fs::write(&checkpoint, b"state").unwrap();
        std::fs::write(dir.path().join("records"), b"not a directory").unwrap();
        let (mut envelope, map) = private_envelope(9, salt);
        envelope.proof = Some(record_for(&envelope, &map));
        finish_upload_checkpoint(&checkpoint, Some(&envelope), b"");
        assert_eq!(std::fs::read(&checkpoint).unwrap(), b"state");
        assert_eq!(
            std::fs::read(checkpoint.with_extension("salt")).unwrap(),
            salt.to_vec()
        );
        assert!(forget_kept(dir.path(), &envelope.address()).is_err());
    }

    #[tokio::test]
    async fn file_data_map_is_the_map_an_upload_of_the_file_computes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.bin");
        let bytes: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        // The upload path (`encrypt_file_to_spill`): streamed encryption,
        // its chunks spilled to disk.
        let (mut chunks, map, handle) = spawn_file_encryption(path.clone()).unwrap();
        let mut spill = ChunkSpill::new().unwrap();
        while let Some(content) = chunks.recv().await {
            spill.push(&content).unwrap();
        }
        handle.await.unwrap().unwrap();
        let uploaded = map.await.unwrap();
        let local = file_data_map(&path).await.unwrap();
        assert!(local == uploaded);
        // The same as encrypting the bytes in memory.
        let (in_memory, _) = self_encryption::encrypt(Bytes::from(bytes)).unwrap();
        assert!(local == in_memory);
        // And its chunks are the ones the upload stores.
        let stored: HashSet<[u8; 32]> = spill.addresses.iter().copied().collect();
        assert_eq!(stored.len(), local.infos().len());
        assert!(local
            .infos()
            .iter()
            .all(|info| stored.contains(&info.dst_hash.0)));
    }

    #[test]
    fn an_extra_chunk_priced_alone_is_exact_only_when_all_content_was_sampled() {
        use CostEstimateConfidence::{AllSamplesAlreadyStoredIncomplete, PricedSample};
        // A live price for the content: a priced sample, however much was
        // sampled.
        assert_eq!(priced_confidence(false, 1, 100), PricedSample);
        assert_eq!(priced_confidence(false, 5, 5), PricedSample);
        // Every content chunk sampled and stored: the extra chunk is all
        // there is to pay.
        assert_eq!(priced_confidence(true, 3, 3), PricedSample);
        assert_eq!(priced_confidence(true, 5, 5), PricedSample);
        // Five of six sampled: the sixth may still need paying.
        assert_eq!(
            priced_confidence(true, ESTIMATE_SAMPLE_CAP, ESTIMATE_SAMPLE_CAP + 1),
            AllSamplesAlreadyStoredIncomplete
        );
        assert_eq!(
            priced_confidence(true, 5, 1_000),
            AllSamplesAlreadyStoredIncomplete
        );
    }

    #[test]
    fn an_outside_payers_checkpoint_is_its_own() {
        let network = ant_protocol::evm::Network::ArbitrumOne;
        let records = [([1u8; 32], 10u64), ([2u8; 32], 20)];
        let scope = |envelope: Option<&[u8]>, payer: Option<&[u8]>| {
            upload_checkpoint_scope(&network, &records, envelope, payer).unwrap()
        };
        // A wallet upload without an envelope: as before, so its saved
        // checkpoints still resume.
        assert_eq!(
            scope(None, None),
            rmp_serde::to_vec(&(&network, records.to_vec())).unwrap()
        );
        // Each payer's own, even without an envelope, so two payers of the
        // same file neither share a payment nor wait on one lock.
        let one = scope(None, Some(b"upload one"));
        assert_eq!(one, scope(None, Some(b"upload one")));
        assert_ne!(one, scope(None, Some(b"upload two")));
        assert_ne!(one, scope(None, None));
        // A payer that names no one still never shares a wallet's.
        assert_ne!(scope(None, Some(b"")), scope(None, None));
        // An envelope's scope names its payer already: unchanged.
        let envelope = envelope_checkpoint_scope(&EnvelopeOptions::private(), b"upload one");
        assert_eq!(
            scope(Some(&envelope), Some(b"upload one")),
            rmp_serde::to_vec(&(&network, records.to_vec(), &envelope[..])).unwrap()
        );
        assert_eq!(
            scope(Some(&envelope), Some(b"upload one")),
            scope(Some(&envelope), None)
        );
    }

    #[test]
    fn an_envelope_checkpoint_belongs_to_its_payer() {
        let options = EnvelopeOptions::private();
        let one = envelope_checkpoint_scope(&options, b"agent one");
        assert_eq!(one, envelope_checkpoint_scope(&options, b"agent one"));
        assert_ne!(one, envelope_checkpoint_scope(&options, b"agent two"));
        assert_ne!(one, envelope_checkpoint_scope(&options, b""));
        assert_ne!(
            one,
            envelope_checkpoint_scope(&EnvelopeOptions::unlisted(), b"agent one")
        );
        // Without a payer scope, as before.
        assert_eq!(envelope_checkpoint_scope(&options, b""), options.scope());
        // Kept records too.
        let dir = Path::new("/data");
        let address = [3u8; 32];
        assert_ne!(
            kept_path(dir, &address, b"agent one", "record"),
            kept_path(dir, &address, b"agent two", "record")
        );
    }

    #[test]
    fn external_envelope_uploads_are_paid_per_chunk_or_refused() {
        use crate::data::client::merkle::DEFAULT_MERKLE_THRESHOLD;
        let envelope = Visibility::Envelope(EnvelopeOptions::private());
        let below = DEFAULT_MERKLE_THRESHOLD - 1;
        // Under the merkle threshold the whole upload is one wave batch.
        for mode in [PaymentMode::Auto, PaymentMode::Single] {
            assert_eq!(
                external_payment_mode(&envelope, below, mode).unwrap(),
                PaymentMode::Single
            );
        }
        // Asked for explicitly, per chunk whatever the size.
        assert_eq!(
            external_payment_mode(&envelope, 10_000, PaymentMode::Single).unwrap(),
            PaymentMode::Single
        );
        // Merkle batches can't carry the envelope's payment: refused before
        // anything is quoted or paid, never silently paid per chunk.
        for (chunks, mode) in [
            (DEFAULT_MERKLE_THRESHOLD, PaymentMode::Auto),
            (10_000, PaymentMode::Auto),
            (2, PaymentMode::Merkle),
            (below, PaymentMode::Merkle),
        ] {
            let error = external_payment_mode(&envelope, chunks, mode).unwrap_err();
            assert!(
                matches!(&error, Error::InvalidData(text) if text.contains("file_upload_with_payer")),
                "{error}"
            );
        }
        // Without an envelope, the caller's mode stands.
        for visibility in [Visibility::Public, Visibility::Private] {
            for mode in [PaymentMode::Auto, PaymentMode::Merkle, PaymentMode::Single] {
                for chunks in [3, 10_000] {
                    assert_eq!(
                        external_payment_mode(&visibility, chunks, mode).unwrap(),
                        mode
                    );
                }
            }
        }
    }

    #[test]
    fn the_cost_estimate_counts_the_chunk_an_upload_adds() {
        let (map, _) = self_encryption::encrypt(Bytes::from(vec![8u8; 4000])).unwrap();
        assert!(extra_upload_chunk(&Visibility::Private, &map)
            .unwrap()
            .is_none());
        // A plain public upload adds its data map chunk.
        let (address, bytes) = extra_upload_chunk(&Visibility::Public, &map)
            .unwrap()
            .unwrap();
        assert_eq!(
            (address, bytes.clone()),
            crate::client_engine::files::public_map_record(&map).unwrap()
        );
        // A readable envelope is the same chunk the upload stores.
        let unlisted = Visibility::Envelope(EnvelopeOptions::unlisted());
        let (address, _) = extra_upload_chunk(&unlisted, &map).unwrap().unwrap();
        let (envelope, _) =
            build_upload_envelope(&EnvelopeOptions::unlisted(), &map, None).unwrap();
        assert_eq!(address, envelope.address());
        // A private one gets a new salt each time, as an upload does, so it
        // is never already stored.
        let private = Visibility::Envelope(EnvelopeOptions::private());
        let first = extra_upload_chunk(&private, &map).unwrap().unwrap();
        let second = extra_upload_chunk(&private, &map).unwrap().unwrap();
        assert_ne!(first.0, second.0);
        assert_eq!(first.1.len(), second.1.len());
    }

    #[test]
    fn the_envelope_record_comes_from_its_own_chunk_proof() {
        let options = EnvelopeOptions::unlisted();
        let (map, _) = self_encryption::encrypt(Bytes::from(vec![9u8; 4000])).unwrap();
        let (envelope, _) = build_upload_envelope(&options, &map, None).unwrap();
        let mut chunks = vec![paid_chunk([1; 32]), paid_chunk(envelope.address())];
        chunks[0].proof_bytes = b"content".to_vec();
        chunks[1].proof_bytes = b"envelope".to_vec();
        assert_eq!(
            envelope_payment_proof(Some(&envelope), &chunks),
            Some(b"envelope".to_vec())
        );
        assert_eq!(envelope_payment_proof(None, &chunks), None);
        // Already stored when the upload was prepared: not paid here.
        assert_eq!(envelope_payment_proof(Some(&envelope), &chunks[..1]), None);
    }

    #[test]
    fn chunk_spill_deduplicates_identical_content() {
        let mut spill = ChunkSpill::new().unwrap();
        let data = vec![0xCC; 512];

        spill.push(&data).unwrap();
        spill.push(&data).unwrap(); // same content, should be skipped
        spill.push(&data).unwrap(); // again

        assert_eq!(spill.len(), 1, "duplicate chunks should be deduplicated");
        assert_eq!(
            spill.total_bytes(),
            512,
            "total_bytes should count unique only"
        );

        // Different content should still be added
        let data2 = vec![0xDD; 256];
        spill.push(&data2).unwrap();
        assert_eq!(spill.len(), 2);
        assert_eq!(spill.total_bytes(), 512 + 256);
    }
}

/// Compile-time assertions that Client file method futures are Send.
#[cfg(test)]
mod send_assertions {
    use super::*;

    fn _assert_send<T: Send>(_: &T) {}

    #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
    async fn _file_upload_is_send(client: &Client) {
        let fut = client.file_upload(Path::new("/dev/null"));
        _assert_send(&fut);
    }

    #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
    async fn _file_upload_with_mode_is_send(client: &Client) {
        let fut = client.file_upload_with_mode(Path::new("/dev/null"), PaymentMode::Auto);
        _assert_send(&fut);
    }

    #[allow(
        dead_code,
        unreachable_code,
        unused_variables,
        clippy::diverging_sub_expression
    )]
    async fn _file_download_is_send(client: &Client) {
        let dm: DataMap = todo!();
        let fut = client.file_download(&dm, Path::new("/dev/null"));
        _assert_send(&fut);
    }
}

impl Client {
    async fn upload_merkle_from_spill(
        &self,
        spill: &ChunkSpill,
        addresses: &[[u8; 32]],
        batch_result: &MerkleBatchPaymentResult,
        already_stored_addresses: &[[u8; 32]],
        progress: Option<&mpsc::Sender<UploadEvent>>,
        payment_refusal: Option<&str>,
    ) -> Result<(usize, String, u128, WaveAggregateStats)> {
        let mut total_stored = already_stored_addresses.len();
        let total_chunks = total_stored + addresses.len();
        let mut stored_addresses: Vec<[u8; 32]> = already_stored_addresses.to_vec();
        let mut failed: Vec<([u8; 32], String)> = Vec::new();
        let mut agg_stats = WaveAggregateStats::default();

        // Chunks without a merkle proof cannot be stored: a partial
        // `pay_for_merkle_multi_batch` result carries proofs only for the
        // sub-batches that both settled and produced proofs. Record them as
        // failed (surfaced via `PartialUpload` once the
        // storable chunks have been attempted) rather than letting its
        // "missing proof" error abort the whole file and discard every other
        // chunk's progress.
        let (to_store, missing_proof) =
            partition_addresses_by_proof(addresses, &batch_result.proofs);
        if !missing_proof.is_empty() {
            match payment_refusal {
                Some(reason) => warn!(
                    "{} chunk(s) lack a merkle proof ({reason}); reporting them as failed",
                    missing_proof.len()
                ),
                None => warn!(
                    "{} chunk(s) lack a merkle proof (partial payment); reporting them as failed",
                    missing_proof.len()
                ),
            }
            for addr in &missing_proof {
                let hex_addr = hex::encode(addr);
                failed.push((
                    *addr,
                    match payment_refusal {
                        Some(reason) => format!("No merkle proof for chunk {hex_addr}: {reason}"),
                        None => format!("Missing merkle proof for chunk {hex_addr}"),
                    },
                ));
            }
        }

        let store_limiter = self.controller().store.clone();

        // Store one chunk to its (freshly re-collected) close group, reusing the
        // chunk's merkle proof. Reads the body from the on-disk spill on demand,
        // so the whole-file store runs as ONE cap-bounded fan-out with no per-wave
        // barrier: a slow straggler (e.g. a chunk whose close-group peers are
        // stale relayed addresses that take minutes to revalidate) no longer
        // holds back the rest of the file. Only the ≤cap in-flight stores hold a
        // body, so peak resident memory is `cap × MAX_CHUNK_SIZE`; the cap is
        // clamped to `MERKLE_STORE_MAX_IN_FLIGHT` (below) so it stays within the
        // ~256 MiB bound the fixed 64-chunk waves gave even if `adaptive.max.store`
        // is configured above 64.
        // Shared across every deferred round so a converged routing table yields
        // a fresh group. Only a quorum shortfall is recoverable; a missing proof
        // or a failed spill read stays fatal. Mirrors `merkle_upload_chunks`.
        let store_one = |addr: [u8; 32]| {
            let limiter = store_limiter.clone();
            let proof_bytes = batch_result.proofs.get(&addr).cloned();
            async move {
                let started = std::time::Instant::now();
                let proof = proof_bytes.ok_or_else(|| {
                    Error::Payment(format!(
                        "Missing merkle proof for chunk {}",
                        hex::encode(addr)
                    ))
                })?;
                let content = spill.read_chunk(&addr)?;
                let peers = self.put_target_peers(&addr).await?;
                observe_op(
                    &limiter,
                    || async move { self.chunk_put_to_close_group(content, proof, &peers).await },
                    classify_error,
                )
                .await
                .map(|_| started)
            }
        };

        info!(
            "Storing {} chunks (merkle) as a single cap-bounded pass — {total_stored}/{total_chunks} stored so far",
            to_store.len()
        );

        // Store the WHOLE file in one cap-bounded fan-out (`max_attempts = 1`, no
        // backoff): no wave barrier, so a slow straggler (dead-relay peers) can't
        // hold back the rest of the file. The store cap re-reads the limiter per
        // slot, so it maxes at 64 → ≤64 bodies resident (bodies read from spill on
        // demand by `store_one`), the same peak-memory bound the fixed 64-chunk
        // waves gave. Quorum-short chunks are collected and deferred to the
        // post-pass concurrent retry rather than parking slots behind a backoff.
        // `merkle_store_cap` clamps to `MERKLE_STORE_MAX_IN_FLIGHT` so a high
        // configured `adaptive.max.store` can't hold more than the wave-era
        // ~256 MB of spilled bodies resident (PR #137 review).
        let cap = || merkle_store_cap(store_limiter.current());
        let outcome = merkle_store_with_retry(
            to_store.clone(),
            cap,
            1,
            std::time::Duration::ZERO,
            progress,
            total_stored,
            total_chunks,
            &store_one,
        )
        .await?;

        // Record confirmed stores from the explicit set the store helper reports.
        // Using that set (rather than inferring "chunks minus failed") keeps
        // `stored_addresses` correct even when a fatal abort leaves some chunks
        // neither stored nor reported short of quorum.
        stored_addresses.extend(&outcome.stored_addresses);
        total_stored = outcome.stored;

        // Merge store stats (durations, attempts, per-round histogram).
        agg_stats.chunk_attempts_total = agg_stats
            .chunk_attempts_total
            .saturating_add(outcome.stats.chunk_attempts_total);
        agg_stats
            .store_durations_ms
            .extend(outcome.stats.store_durations_ms);
        for (slot, count) in agg_stats
            .retries_histogram
            .iter_mut()
            .zip(outcome.stats.retries_histogram.iter())
        {
            *slot = slot.saturating_add(*count);
        }

        if let Some(e) = outcome.fatal {
            // A non-quorum store error is fatal (missing proofs were filtered out
            // above, so this is a genuine network/store failure). Preserve every
            // chunk stored so far and report every not-stored chunk as failed, so
            // the `PartialUpload` counts are accurate.
            warn!("merkle store aborted: {e}");
            let mut known_failed = failed;
            known_failed.extend(outcome.failed_addresses);
            return Err(partial_upload_after_fatal(
                addresses,
                stored_addresses,
                total_stored,
                total_chunks,
                known_failed,
                PartialUploadSpend {
                    storage_cost_atto: batch_result.storage_cost_atto.clone(),
                    gas_cost_wei: batch_result.gas_cost_wei,
                },
                merkle_fatal_reason(
                    &format!("merkle chunk store aborted: {e}"),
                    missing_proof.len(),
                    payment_refusal,
                ),
            ));
        }

        // Non-fatal: quorum-short chunks are deferred (not failed yet) for the
        // post-pass concurrent retry. A deferred chunk joins `stored_addresses`
        // only if/when a later round stores it.
        let deferred: Vec<([u8; 32], String)> = outcome.failed_addresses;

        // The store pass never blocked on backoff; now retry the deferred set in
        // concurrent rounds. Bodies are re-read from the spill by `store_one`
        // (peak RAM unchanged) and proofs re-attached. Chunks still short after
        // the final round become `failed`; a non-quorum error aborts as
        // `PartialUpload`.
        if !deferred.is_empty() {
            info!(
                "Deferring {} merkle chunk(s) short of quorum for concurrent retry after the store pass",
                deferred.len()
            );
            let dr = merkle_deferred_retry(
                deferred,
                &DEFERRED_ROUND_DELAYS_SECS,
                |n: usize| merkle_store_cap(store_limiter.current()).min(n.max(1)),
                progress,
                total_stored,
                total_chunks,
                &store_one,
            )
            .await?;

            stored_addresses.extend(dr.stored_addresses);
            total_stored = dr.stored;

            // Merge the deferred pass's stats — its histogram is already mapped
            // to the right per-round slots — into the file aggregate.
            agg_stats.chunk_attempts_total = agg_stats
                .chunk_attempts_total
                .saturating_add(dr.stats.chunk_attempts_total);
            agg_stats
                .store_durations_ms
                .extend(dr.stats.store_durations_ms);
            for (slot, count) in agg_stats
                .retries_histogram
                .iter_mut()
                .zip(dr.stats.retries_histogram.iter())
            {
                *slot = slot.saturating_add(*count);
            }

            if let Some(reason) = dr.fatal {
                // A non-quorum store error during a deferred round is fatal, the
                // same as in the wave path: preserve everything stored so far and
                // report every not-stored chunk as failed.
                warn!("merkle deferred retry aborted: {reason}");
                let mut known_failed = failed;
                known_failed.extend(dr.failed_addresses);
                return Err(partial_upload_after_fatal(
                    addresses,
                    stored_addresses,
                    total_stored,
                    total_chunks,
                    known_failed,
                    PartialUploadSpend {
                        storage_cost_atto: batch_result.storage_cost_atto.clone(),
                        gas_cost_wei: batch_result.gas_cost_wei,
                    },
                    merkle_fatal_reason(
                        &format!("merkle chunk store aborted: {reason}"),
                        missing_proof.len(),
                        payment_refusal,
                    ),
                ));
            }
            failed.extend(dr.failed_addresses);
        }

        // A file with any permanently-failed chunk is not fully stored — surface
        // it as `PartialUpload`, but only after the store pass and every deferred
        // retry round are exhausted (never silently succeed with missing chunks).
        if !failed.is_empty() {
            let failed_count = failed.len();
            let total_attempts = 1 + DEFERRED_ROUND_DELAYS_SECS.len();
            let reason = merkle_partial_reason(
                failed_count,
                missing_proof.len(),
                total_attempts,
                payment_refusal,
            );
            warn!(
                "merkle upload incomplete: {failed_count}/{total_chunks} chunks failed — {reason}"
            );
            return Err(Error::PartialUpload {
                stored: stored_addresses,
                stored_count: total_stored,
                failed,
                failed_count,
                total_chunks,
                spend: Box::new(PartialUploadSpend {
                    storage_cost_atto: batch_result.storage_cost_atto.clone(),
                    gas_cost_wei: batch_result.gas_cost_wei,
                }),
                reason,
            });
        }

        Ok((
            total_stored,
            batch_result.storage_cost_atto.clone(),
            batch_result.gas_cost_wei,
            agg_stats,
        ))
    }
}

#[cfg(test)]
mod payer_tests {
    use super::*;
    use crate::data::client::batch::ChunkPaymentPlan;
    use crate::data::client::upload::{MerkleUploadPayment, UploadPayment};

    /// A payer that refuses everything, to show errors reach the caller.
    struct RefusingPayer;

    #[async_trait::async_trait]
    impl UploadPayer for RefusingPayer {
        async fn pay_quotes(&self, _plans: &[ChunkPaymentPlan]) -> Result<UploadPayment> {
            Err(Error::Payment("refused".into()))
        }

        async fn pay_merkle(&self, _batch: &PreparedMerkleBatch) -> Result<MerkleUploadPayment> {
            Err(Error::Payment("refused".into()))
        }
    }

    #[tokio::test]
    async fn a_payer_works_as_a_trait_object() {
        let payer: &dyn UploadPayer = &RefusingPayer;
        let result = payer.pay_quotes(&[]).await;
        assert!(matches!(result, Err(Error::Payment(reason)) if reason == "refused"));
        // A payer that doesn't name itself is one payer.
        assert!(payer.checkpoint_scope().is_empty());
    }
}
