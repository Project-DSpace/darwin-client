use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Subcommand;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::info;

use ant_core::ant_listings::{EnvelopeProof, Metadata, PaymentField, ShownFields};
use ant_core::data::{
    file_data_map, forget_upload_record, proof_data_map, shown_after_hiding,
    spawn_download_diagnostics_writer, Client, CollisionPolicy, CostEstimateConfidence,
    DownloadEvent, EnvelopeOptions, Error as DataError, EvmNetwork, FileChunkPeerReport,
    FileChunkPeerReportPeer, FileChunkPeerStatus, FileChunkPeerSweepReport, ListingChain,
    PaymentMode, UploadEvent,
};
use ant_core::datamap_file::{
    original_name_from_datamap, read_datamap, read_record, record_path_for, write_record,
    write_upload_files, UploadFiles,
};

use super::chunk::{parse_address, xor_distance_decimal};
use crate::progress;

/// Values of `darwin file upload --visibility`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum VisibilityArg {
    /// Only the holder of the data map can read the file (`--readable no
    /// --index no`).
    Private,
    /// Anyone with the address can read the file (`--readable yes --index
    /// no`).
    Unlisted,
    /// Anyone can read the file, and it appears in the listings index
    /// (`--readable yes --index yes`).
    Listed,
}

/// Parse `yes` or `no` (also `true` or `false`).
fn parse_yes_no(value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        _ => Err(format!("expected yes or no, not {value:?}")),
    }
}

/// The upload choices `darwin file upload` and `darwin file cost` take.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct UploadChoices {
    /// Public mode: store the data map on the network (anyone with the
    /// address can download). Same as `--visibility unlisted`. Default is
    /// private (data map saved locally).
    #[arg(long)]
    public: bool,
    /// Shorthand for `--readable` and `--index`: `private` (the default:
    /// no, no), `unlisted` (yes, no) or `listed` (yes, yes).
    #[arg(long, value_enum, conflicts_with_all = ["public", "readable", "index"])]
    visibility: Option<VisibilityArg>,
    /// Whether anyone with the address can read the file (`yes`), or only
    /// the holder of the data map (`no`, the default: the envelope stores
    /// a salted hash of it).
    #[arg(long, value_name = "yes|no", value_parser = parse_yes_no, conflicts_with = "public")]
    readable: Option<bool>,
    /// Whether the file appears in the listings index (default `no`).
    #[arg(long, value_name = "yes|no", value_parser = parse_yes_no, conflicts_with = "public")]
    index: Option<bool>,
    /// Payment fields to hide from anyone but you, comma-separated:
    /// `tx-hash`, `block`, `timestamp`, `log-index`, `quote`, or `all`.
    /// All are shown by default. Hiding all on an upload that is not in
    /// the index and has no name or content type stores no envelope.
    #[arg(long, value_delimiter = ',', value_name = "FIELDS")]
    hide: Vec<String>,
    /// A name stored in the envelope, on any visibility. Public and
    /// permanent: on a private file, anyone with the envelope's address
    /// can read it, though not the file.
    #[arg(long)]
    name: Option<String>,
    /// A content type stored in the envelope, such as `application/pdf`,
    /// on any visibility. Public and permanent, like `--name`.
    #[arg(long)]
    content_type: Option<String>,
}

impl UploadChoices {
    /// The upload options these flags ask for.
    fn options(&self) -> anyhow::Result<EnvelopeOptions> {
        upload_options(
            self.public,
            self.visibility,
            self.readable,
            self.index,
            &self.hide,
            self.name.clone(),
            self.content_type.clone(),
        )
    }
}

/// File subcommands.
#[derive(Subcommand, Debug)]
pub enum FileAction {
    /// Upload a file to the network with EVM payment.
    Upload {
        /// Path to the file to upload.
        path: PathBuf,
        /// Who can read it, whether it is listed, which payment fields are
        /// hidden, and its metadata.
        #[command(flatten)]
        choices: UploadChoices,
        /// Force merkle batch payment regardless of chunk count (min 2 chunks).
        /// Reduces gas costs for batches by paying in a single transaction.
        #[arg(long, conflicts_with = "no_merkle")]
        merkle: bool,
        /// Disable merkle batch payment, always use per-chunk payments.
        #[arg(long, conflicts_with = "merkle")]
        no_merkle: bool,
        /// **Deprecated.** Per-upload override for the store timeout
        /// (seconds). The adaptive controller now sizes timeouts from
        /// observed RTT; this override is retained for one release.
        #[arg(long, hide = true)]
        store_timeout: Option<u64>,
        /// **Deprecated.** Per-upload override for store concurrency.
        /// The adaptive controller now sizes concurrency from observed
        /// signals; this override is retained for one release.
        #[arg(long, hide = true)]
        store_concurrency: Option<usize>,
        /// Replace any existing `<filename>.datamap` (and `<filename>.record`)
        /// instead of writing a suffixed `<filename>-2.datamap`. Restores the
        /// pre-helper behaviour for scripts that re-upload the same path
        /// repeatedly. An old record holds the salt that proves its upload,
        /// and a private upload's record also holds its data map, so it reads
        /// the file like the `.datamap`: keep a copy first.
        #[arg(long)]
        overwrite: bool,
    },
    /// Download a file from the network.
    ///
    /// Public:  `darwin file download ADDRESS -o output.pdf`
    /// Private: `darwin file download --datamap photo.jpg.datamap`
    /// Private (custom output): `darwin file download --datamap photo.jpg.datamap -o keep.jpg`
    /// Revealed: `darwin file download --proof photo.jpg.proof -o photo.jpg`
    Download {
        /// Hex-encoded address (public data map or envelope address).
        /// Required unless --datamap or --proof is provided.
        #[arg(required_unless_present_any = ["datamap", "proof"])]
        address: Option<String>,
        /// Path to a local data map file (for private downloads). Given with
        /// an address (a private file's envelope), the data map is used, and
        /// checked against the envelope if the upload's record is next to it.
        #[arg(long, conflicts_with = "proof")]
        datamap: Option<PathBuf>,
        /// Path to an upload record or proof (`darwin file prove`) whose
        /// envelope carries the data map or reveals it.
        #[arg(long, conflicts_with = "address")]
        proof: Option<PathBuf>,
        /// Output file path. Required for `--address` downloads. Optional for
        /// `--datamap` downloads — defaults to the original filename derived
        /// from the datamap basename (e.g. `photo.jpg.datamap` → `photo.jpg`,
        /// written to the current directory).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Number of closest peers to try for each chunk fetch.
        #[arg(long, alias = "peer-count", value_name = "COUNT")]
        peers: Option<NonZeroUsize>,
        /// Fetch each file chunk from every selected closest peer and print
        /// ranked per-peer results after a successful download.
        #[arg(long, alias = "try-all-peers")]
        all_peers: bool,
        /// Write one JSONL record per normal-path chunk fetch attempt.
        #[arg(long, value_name = "PATH", conflicts_with = "all_peers")]
        download_diagnostics: Option<PathBuf>,
    },
    /// Write a proof of an upload from its record (`<file>.record`): the
    /// envelope, its payment's transaction and paid quote, and for a private
    /// file the data map and salt, which reveal the file to whoever has the
    /// proof. Anyone can check it from the chain alone with `darwin file verify`.
    Prove {
        /// The upload's record, saved next to its data map.
        record: PathBuf,
        /// Where to write the proof (default: the record's name with
        /// `.proof`).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// For a private file: prove the payment without revealing the data
        /// map and salt. The proof then shows that the envelope was paid
        /// for, not which file it is for.
        #[arg(long)]
        no_reveal: bool,
        /// Replace the output file if it exists. The record itself is never
        /// replaced: it holds the salt, which nothing else keeps.
        #[arg(long)]
        force: bool,
    },
    /// Check an upload proof (or record) from the payment chain alone, and
    /// optionally that a local file is the one it is for. Needs no storage
    /// node.
    Verify {
        /// The proof, as `darwin file prove` writes it.
        proof: PathBuf,
        /// A local file to compare with the proof's data map.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Estimate the cost of uploading a file without uploading.
    ///
    /// Encrypts the file locally to determine chunk count, then queries
    /// the network for a price quote. No payment or wallet required.
    Cost {
        /// Path to the file to estimate.
        path: PathBuf,
        /// The upload's choices, as `darwin file upload` takes them: an envelope
        /// (the default) or a public data map adds one chunk.
        #[command(flatten)]
        choices: UploadChoices,
        /// Force merkle batch payment mode for the estimate.
        #[arg(long, conflicts_with = "no_merkle")]
        merkle: bool,
        /// Force single payment mode for the estimate.
        #[arg(long, conflicts_with = "merkle")]
        no_merkle: bool,
    },
}

impl FileAction {
    /// Check the upload choices (`--hide`, `--name`, `--content-type`) of
    /// `upload` and `cost`, so a mistake is named before the wallet key is
    /// asked for or the network is joined.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            FileAction::Upload { choices, .. } | FileAction::Cost { choices, .. } => {
                choices.options().map(|_| ())
            }
            _ => Ok(()),
        }
    }

    /// Whether the action needs a connection to the storage network.
    /// `prove` works offline and `verify` reads only the payment chain.
    pub fn needs_network(&self) -> bool {
        !matches!(self, FileAction::Prove { .. } | FileAction::Verify { .. })
    }

    /// Run an action that needs no storage network. `evm_network` resolves
    /// the payment chain, for `verify` only.
    pub async fn execute_offline(
        self,
        json: bool,
        evm_network: impl FnOnce() -> anyhow::Result<EvmNetwork>,
    ) -> anyhow::Result<()> {
        match self {
            FileAction::Prove {
                record,
                output,
                no_reveal,
                force,
            } => handle_file_prove(&record, output, no_reveal, force, json),
            FileAction::Verify { proof, file } => {
                let chain = ListingChain::new(&evm_network()?)?;
                handle_file_verify(&chain, &proof, file.as_deref(), json).await
            }
            _ => anyhow::bail!("this command needs the network"),
        }
    }

    /// Return per-upload client config overrides, if any.
    pub fn upload_overrides(&self) -> (Option<u64>, Option<usize>) {
        match self {
            FileAction::Upload {
                store_timeout,
                store_concurrency,
                ..
            } => (*store_timeout, *store_concurrency),
            _ => (None, None),
        }
    }
}

/// Resolve the on-disk output path for `file download`.
///
/// `--address` downloads have nothing to derive from, so `-o/--output` is
/// mandatory. `--datamap` downloads default to the original filename baked
/// into the datamap basename (`photo.jpg.datamap` → `photo.jpg`), written
/// to the current working directory.
fn resolve_download_output(
    output: Option<PathBuf>,
    datamap: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    if let Some(p) = output {
        return Ok(p);
    }
    let dm = datamap.ok_or_else(|| {
        anyhow::anyhow!("-o/--output is required when downloading by address or --proof")
    })?;
    let basename = original_name_from_datamap(dm).ok_or_else(|| {
        anyhow::anyhow!(
            "Cannot derive output filename from {}; pass -o/--output explicitly",
            dm.display()
        )
    })?;
    Ok(PathBuf::from(basename))
}

impl FileAction {
    /// Run an action on the network. `token` is the payment token's symbol,
    /// which costs are shown in.
    pub async fn execute(self, client: &Client, json: bool, token: &str) -> anyhow::Result<()> {
        match self {
            FileAction::Upload {
                path,
                choices,
                merkle,
                no_merkle,
                store_timeout: _,
                store_concurrency: _,
                overwrite,
            } => {
                let mode = if merkle {
                    PaymentMode::Merkle
                } else if no_merkle {
                    PaymentMode::Single
                } else {
                    PaymentMode::Auto
                };
                let policy = if overwrite {
                    CollisionPolicy::Overwrite
                } else {
                    CollisionPolicy::NumericSuffix
                };
                let options = choices.options()?;
                handle_file_upload(client, &path, options, mode, policy, json, token).await
            }
            FileAction::Download {
                address,
                datamap,
                proof,
                output,
                peers,
                all_peers,
                download_diagnostics,
            } => {
                let resolved_output = resolve_download_output(output, datamap.as_deref())?;
                handle_file_download(
                    client,
                    address.as_deref(),
                    datamap.as_deref(),
                    proof.as_deref(),
                    resolved_output,
                    json,
                    peers,
                    all_peers,
                    download_diagnostics.as_deref(),
                )
                .await
            }
            FileAction::Cost {
                path,
                choices,
                merkle,
                no_merkle,
            } => {
                let mode = if merkle {
                    PaymentMode::Merkle
                } else if no_merkle {
                    PaymentMode::Single
                } else {
                    PaymentMode::Auto
                };
                let options = choices.options()?;
                handle_file_cost(client, &path, options, mode, json, token).await
            }
            action @ (FileAction::Prove { .. } | FileAction::Verify { .. }) => {
                let network = client.wallet().map(|wallet| wallet.network().clone());
                action
                    .execute_offline(json, || {
                        network.ok_or_else(|| anyhow::anyhow!("no payment chain configured"))
                    })
                    .await
            }
        }
    }
}

/// The upload choices the flags ask for. `--visibility` (or `--public`) sets
/// `--readable` and `--index` together; without them both default to `no`.
/// Every payment field is shown unless `--hide` names it.
fn upload_options(
    public: bool,
    visibility: Option<VisibilityArg>,
    readable: Option<bool>,
    index: Option<bool>,
    hide: &[String],
    name: Option<String>,
    content_type: Option<String>,
) -> anyhow::Result<EnvelopeOptions> {
    let mut options = match visibility {
        Some(VisibilityArg::Listed) => EnvelopeOptions::listed(),
        Some(VisibilityArg::Unlisted) => EnvelopeOptions::unlisted(),
        Some(VisibilityArg::Private) => EnvelopeOptions::private(),
        None if public => EnvelopeOptions::unlisted(),
        None => EnvelopeOptions::private(),
    };
    if let Some(readable) = readable {
        options.readable = readable;
    }
    if let Some(index) = index {
        options.in_index = index;
    }
    options.shown =
        shown_after_hiding(hide.iter().map(String::as_str)).map_err(|e| anyhow::anyhow!(e))?;
    options.metadata = Metadata { content_type, name };
    options
        .validate()
        .map_err(|e| anyhow::anyhow!("Invalid --name or --content-type: {e}"))?;
    Ok(options)
}

/// The names of the payment fields `options` hides.
fn hidden_names(options: &EnvelopeOptions) -> Vec<&'static str> {
    options.shown.hidden().map(PaymentField::name).collect()
}

async fn handle_file_upload(
    client: &Client,
    path: &Path,
    options: EnvelopeOptions,
    mode: PaymentMode,
    collision_policy: CollisionPolicy,
    json_output: bool,
    token: &str,
) -> anyhow::Result<()> {
    let file_size = std::fs::metadata(path)?.len();
    if file_size < 3 {
        anyhow::bail!("File too small: self-encryption requires at least 3 bytes");
    }
    let start = Instant::now();

    info!(
        "Uploading file: {} ({file_size} bytes, payment mode: {mode:?})",
        path.display()
    );

    // Said before anything is paid; the choice stays the uploader's.
    let warnings: Vec<String> = options.warnings().iter().map(ToString::to_string).collect();
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    let visibility = options.clone().into_visibility();

    let upload_outcome = if json_output {
        // No progress bars in JSON mode.
        client
            .file_upload_with_visibility_and_progress(path, mode, visibility, None)
            .await
    } else {
        // Set up progress channel and drive progress bars
        let (tx, rx) = mpsc::channel(64);
        let pb_handle = tokio::spawn(drive_upload_progress(
            rx,
            path.display().to_string(),
            file_size,
        ));

        let upload_result = client
            .file_upload_with_visibility_and_progress(path, mode, visibility, Some(tx))
            .await;

        // Wait for progress display to finish (sender dropped → receiver exits)
        let _ = pb_handle.await;

        upload_result
    };

    let result = match upload_outcome {
        Ok(r) => r,
        Err(DataError::PartialUpload {
            stored_count,
            failed_count,
            total_chunks,
            spend,
            reason,
            ..
        }) => {
            if json_output {
                let out = UploadFailureJson {
                    error: "partial_upload",
                    total_chunks,
                    chunks_stored: stored_count,
                    chunks_failed: failed_count,
                    storage_cost_atto: spend.storage_cost_atto.clone(),
                    gas_cost_wei: spend.gas_cost_wei.to_string(),
                    reason: &reason,
                };
                println!("{}", serde_json::to_string(&out)?);
            }
            // The partial upload still spent money on-chain for the chunks it
            // paid for; report it so the user knows what the failed attempt cost.
            let cost_display = format_cost(&spend.storage_cost_atto, spend.gas_cost_wei, token);
            anyhow::bail!(
                "Upload failed: {stored_count}/{total_chunks} stored, {failed_count} failed \
                 (spent {cost_display}): {reason}"
            );
        }
        Err(e) => anyhow::bail!("File upload failed: {e}"),
    };

    let elapsed = start.elapsed();
    let envelope = result.envelope.as_ref();
    let record = envelope.and_then(|envelope| envelope.proof.as_ref());

    // The data map stays local unless anyone can read the file; the record
    // (envelope, payment, and a private file's salt) is saved next to it.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let original_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| {
            anyhow::anyhow!("Cannot determine source filename from {}", path.display())
        })?;
    let local_map = (!options.readable).then_some(&result.data_map);
    let (files, save_problem) =
        match write_upload_files(parent, &original_name, local_map, record, collision_policy) {
            Ok(files) => (files, None),
            Err(e) => {
                if let Some(text) = record.and_then(|record| record.to_hex().ok()) {
                    eprintln!(
                        "The upload's record, which could not be saved (a copy stays under \
                         the client's data directory, in payments/upload/records/):\n{text}"
                    );
                }
                if local_map.is_some() {
                    anyhow::bail!("Failed to save the upload's files: {e}");
                }
                // A readable file is on the network at its address: say the
                // record wasn't saved, and still print the result.
                let files = UploadFiles {
                    datamap: None,
                    record: None,
                };
                (files, Some(format!("the record could not be saved: {e}")))
            }
        };
    if let (Some(_), Some(envelope)) = (&files.record, envelope) {
        // The record is saved: the copy the upload kept can go.
        if let Err(e) = forget_upload_record(&envelope.address()) {
            info!("Could not remove the upload's kept record: {e}");
        }
    }
    let saved = files.record.is_some();
    let record_problem = join_problems(
        save_problem,
        envelope.and_then(|envelope| {
            record_note(
                envelope.proof.is_some(),
                envelope.proof_checked,
                envelope.proof_problem.as_deref(),
                saved,
            )
        }),
    );
    if let Some(note) = &record_problem {
        eprintln!("warning: {note}");
    }
    if let Some(envelope) = envelope.filter(|envelope| envelope.proof.is_none()) {
        // Without a record, the salt would be lost: say it once.
        if let Some(salt) = envelope.salt {
            eprintln!(
                "The private envelope's salt (keep it with the data map to prove the file): {}",
                hex::encode(salt)
            );
        }
    }

    let address = result.data_map_address.map(hex::encode);
    if options.readable && address.is_none() {
        anyhow::bail!("Public upload completed without a DataMap address");
    }
    let envelope_address = envelope.map(|envelope| hex::encode(envelope.address()));
    let cost_display = format_cost(&result.storage_cost_atto, result.gas_cost_wei, token);

    if json_output {
        let out = UploadJsonResult {
            address: address.clone(),
            datamap: files.datamap.as_ref().map(|p| p.display().to_string()),
            mode: upload_mode(&options).into(),
            chunks: if options.readable {
                result.total_chunks
            } else {
                result.chunks_stored
            },
            total_chunks: result.total_chunks,
            chunks_stored: result.chunks_stored,
            chunks_failed: result.chunks_failed,
            size: file_size,
            storage_cost_atto: result.storage_cost_atto.clone(),
            gas_cost_wei: result.gas_cost_wei.to_string(),
            elapsed_secs: elapsed.as_secs_f64(),
            chunk_attempts_total: result.chunk_attempts_total,
            store_durations_ms: result.store_durations_ms.clone(),
            retries_histogram: result.retries_histogram,
            choices: upload_choices_json(
                &options,
                envelope.map(|envelope| (hex::encode(envelope.address()), envelope.proof_checked)),
                files.record.as_deref(),
                record_problem,
                warnings,
            ),
        };
        println!("{}", serde_json::to_string(&out)?);
        return Ok(());
    }

    println!();
    println!("Upload complete!");
    if let Some(address) = &address {
        println!("  Address:  {address}");
    } else if let Some(datamap) = &files.datamap {
        println!("  Datamap:  {}", datamap.display());
        if let Some(envelope_address) = &envelope_address {
            println!(
                "  Envelope: {envelope_address} ({})",
                private_envelope_note(&options)
            );
        }
    }
    if options.in_index {
        if options.readable {
            println!("  Listed:   yes (see `darwin listings`)");
        } else {
            println!("  Listed:   yes, unreadable until you reveal it (see `darwin listings`)");
        }
    }
    if envelope.is_some() {
        let hidden = hidden_names(&options);
        if hidden.is_empty() {
            println!("  Payment:  all fields shown");
        } else {
            println!("  Payment:  hidden: {}", hidden.join(", "));
        }
    }
    if let Some(record) = &files.record {
        println!("  Record:   {}", record.display());
    }
    println!(
        "  Chunks:   {}",
        chunks_summary(
            result.total_chunks,
            result.chunks_stored,
            envelope.is_some(),
            options.readable
        )
    );
    println!("  Size:     {}", format_size(file_size));
    println!("  Cost:     {cost_display}");
    println!("  Time:     {:.1}s", elapsed.as_secs_f64());
    println!();
    if let Some(address) = &address {
        println!("Anyone can download this file with:");
        println!("  darwin file download {address} -o <FILE>");
    } else if let Some(datamap) = &files.datamap {
        println!("Download this file with:");
        println!("  darwin file download --datamap {}", datamap.display());
    }
    if let Some(record) = &files.record {
        println!("Prove this upload to anyone with:");
        println!("  darwin file prove {}", record.display());
        if !options.readable {
            println!(
                "Keep the record as safe as the data map: it holds the data map and the salt, \
                 so it reads the file, and its salt is what proves which file this is. \
                 `darwin file prove --no-reveal` proves only the payment."
            );
        }
    }

    info!(
        "Upload complete: address={address:?}, envelope={envelope_address:?}, chunks={}",
        result.total_chunks
    );
    Ok(())
}

/// The `mode` an upload's JSON reports, as before envelopes: `listed`,
/// `public` (readable, not in the index) or `private`.
fn upload_mode(options: &EnvelopeOptions) -> &'static str {
    match (options.readable, options.in_index) {
        (true, true) => "listed",
        (true, false) => "public",
        (false, _) => "private",
    }
}

/// What the user should know about an envelope's record: why there is none
/// (`has_record` false), or why it wasn't checked against the chain
/// (`checked` false, `problem` says why). `saved`: whether the record file
/// was written, so `darwin file verify` can check it later.
fn record_note(
    has_record: bool,
    checked: bool,
    problem: Option<&str>,
    saved: bool,
) -> Option<String> {
    match (has_record, problem) {
        (false, Some(problem)) => Some(format!("no record saved: {problem}")),
        (false, None) => Some("no record saved".into()),
        (true, Some(problem)) if !checked && saved => Some(format!(
            "the record is saved but was {problem}; check it later with `darwin file verify`"
        )),
        (true, Some(problem)) if !checked => Some(format!("the record was {problem}")),
        (true, _) => None,
    }
}

/// Two problems with a record, as one.
fn join_problems(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
        (first, second) => first.or(second),
    }
}

/// What the summary says is public about a private upload's envelope.
fn private_envelope_note(options: &EnvelopeOptions) -> String {
    if options.shown != ShownFields::NONE {
        return "its payment record is public, the file is not".into();
    }
    let metadata = &options.metadata;
    let public = match (&metadata.name, &metadata.content_type) {
        (Some(_), Some(_)) => "its name and content type are public",
        (Some(_), None) => "its name is public",
        (None, Some(_)) => "its content type is public",
        (None, None) => "its listing is public",
    };
    format!("{public}; the payment and the file are not")
}

/// The summary's chunk count: every chunk stored, with the envelope or the
/// data map chunk among them called out, as before envelopes.
fn chunks_summary(
    total_chunks: usize,
    chunks_stored: usize,
    envelope: bool,
    readable: bool,
) -> String {
    let extra = match (envelope, readable) {
        (true, _) => "envelope",
        (false, true) => "data map",
        (false, false) => return chunks_stored.to_string(),
    };
    format!(
        "{total_chunks} ({} + 1 {extra})",
        total_chunks.saturating_sub(1)
    )
}

/// What an upload's JSON says about its choices, envelope and record.
/// `envelope` is the envelope's address and whether its record was checked
/// against the chain.
fn upload_choices_json(
    options: &EnvelopeOptions,
    envelope: Option<(String, bool)>,
    record: Option<&Path>,
    record_problem: Option<String>,
    warnings: Vec<String>,
) -> UploadChoicesJson {
    let (envelope_address, record_checked) = envelope.unzip();
    UploadChoicesJson {
        readable: options.readable,
        in_index: options.in_index,
        hidden: hidden_names(options),
        envelope_address,
        record: record.map(|path| path.display().to_string()),
        record_checked,
        record_problem,
        warnings,
    }
}

/// Drive upload progress from the event channel.
///
/// Bars and spinners are routed through the shared `MultiProgress` (see
/// `progress` module), so they coexist with tracing log lines emitted at any
/// verbosity level.
async fn drive_upload_progress(
    mut rx: mpsc::Receiver<UploadEvent>,
    filename: String,
    file_size: u64,
) {
    let bar_style = ProgressStyle::with_template(
        "{spinner:.cyan} {msg}\n  [{bar:40.cyan/dim}] {pos}/{len} chunks",
    )
    .expect("valid template")
    .progress_chars("━╸━")
    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

    let mut pb = progress::new_spinner(&format!(
        "Encrypting {filename} ({})...",
        format_size(file_size)
    ));

    while let Some(event) = rx.recv().await {
        match event {
            UploadEvent::Encrypting { chunks_done } => {
                pb.set_message(format!("Encrypting {filename} ({chunks_done} chunks)..."));
            }
            UploadEvent::Encrypted { total_chunks } => {
                pb.finish_and_clear();
                eprintln!("Encrypted into {total_chunks} chunks");
                pb = progress::attach(ProgressBar::new(total_chunks as u64));
                pb.set_style(bar_style.clone());
                pb.set_message(format!("Uploading {filename}"));
                pb.enable_steady_tick(Duration::from_millis(80));
            }
            UploadEvent::QuotingChunks { .. } => {}
            UploadEvent::ChunkQuoted { quoted, total: _ } => {
                let pos = std::cmp::max(pb.position(), quoted as u64);
                pb.set_position(pos);
            }
            UploadEvent::ChunkStored { stored, total: _ } => {
                let pos = std::cmp::max(pb.position(), stored as u64);
                pb.set_position(pos);
            }
        }
    }

    pb.finish_and_clear();
}

#[allow(clippy::too_many_arguments)]
async fn handle_file_download(
    client: &Client,
    address: Option<&str>,
    datamap_path: Option<&Path>,
    proof_path: Option<&Path>,
    output: PathBuf,
    json_output: bool,
    peer_count: Option<NonZeroUsize>,
    all_peers: bool,
    download_diagnostics: Option<&Path>,
) -> anyhow::Result<()> {
    let output_path = output;
    let start = Instant::now();
    let (diagnostics, diagnostics_writer) = match download_diagnostics {
        Some(path) => {
            let (sender, writer) = spawn_download_diagnostics_writer(path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to open download diagnostics sidecar {}: {e}",
                    path.display()
                )
            })?;
            (Some(sender), Some(writer))
        }
        None => (None, None),
    };

    // Keep the fallible download work inside a result boundary so the
    // diagnostics sender is always closed and its writer joined, including
    // failure paths. Failed downloads are the cases where the final records
    // matter most.
    let download_result: anyhow::Result<Option<FilePeerCheckJson>> = async {
        let data_map = if let Some(dm_path) = datamap_path {
            // A private file's envelope address doesn't give the data map;
            // with --datamap as well, the data map is what reads the file.
            info!("Downloading file using datamap: {}", dm_path.display());
            let map = read_datamap(dm_path)
                .map_err(|e| anyhow::anyhow!("Failed to read datamap: {e}"))?;
            if let Some(addr_hex) = address {
                let address = parse_address(addr_hex)?;
                if let Some(note) = check_datamap_for_address(dm_path, &address, &map)? {
                    eprintln!("warning: {note}");
                }
            }
            map
        } else if let Some(addr_hex) = address {
            info!("Downloading public file from address {addr_hex}");
            let address = parse_address(addr_hex)?;
            if !json_output {
                let spinner = progress::new_spinner("Fetching data map...");
                let result = if let Some(peer_count) = peer_count {
                    client
                        .data_map_fetch_from_closest_peers(&address, peer_count)
                        .await
                } else {
                    client.data_map_fetch(&address).await
                };
                spinner.finish_and_clear();
                result.map_err(data_map_fetch_error)?
            } else {
                if let Some(peer_count) = peer_count {
                    client
                        .data_map_fetch_from_closest_peers(&address, peer_count)
                        .await
                } else {
                    client.data_map_fetch(&address).await
                }
                .map_err(data_map_fetch_error)?
            }
        } else if let Some(proof_path) = proof_path {
            info!("Downloading file using proof: {}", proof_path.display());
            let proof = read_record(proof_path)
                .map_err(|e| anyhow::anyhow!("Failed to read proof: {e}"))?;
            proof_data_map(&proof)
                .map_err(|e| anyhow::anyhow!("The proof gives no data map: {e}"))?
        } else {
            anyhow::bail!("--datamap required for private download");
        };

        let chunk_peer_check = if json_output {
            if all_peers {
                let peer_count = download_peer_check_count(client, peer_count)?;
                let report = client
                    .file_download_with_peer_report_from_closest_peers(
                        &data_map,
                        &output_path,
                        None,
                        peer_count,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("Download failed: {e}"))?;
                Some(file_peer_check_from_reports(report.chunk_reports))
            } else {
                let download_result = if let Some(diagnostics) = diagnostics.clone() {
                    let peer_count = download_peer_check_count(client, peer_count)?;
                    client
                        .file_download_with_progress_and_diagnostics_from_closest_peers(
                            &data_map,
                            &output_path,
                            None,
                            peer_count,
                            Some(diagnostics),
                        )
                        .await
                } else if let Some(peer_count) = peer_count {
                    client
                        .file_download_from_closest_peers(&data_map, &output_path, peer_count)
                        .await
                } else {
                    client.file_download(&data_map, &output_path).await
                };

                download_result.map_err(|e| anyhow::anyhow!("Download failed: {e}"))?;
                None
            }
        } else {
            let (tx, mut rx) = mpsc::channel(64);

            let progress_handle = tokio::spawn(async move {
                let mut pb = progress::new_spinner("Resolving data map...");

                let bar_style = ProgressStyle::with_template(
                    "{spinner:.cyan} Downloading\n  [{bar:40.cyan/dim}] {pos}/{len} chunks",
                )
                .expect("valid template")
                .progress_chars("━╸━")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

                while let Some(event) = rx.recv().await {
                    match event {
                        DownloadEvent::ResolvingDataMap {
                            total_map_chunks: _,
                        } => {
                            pb.set_message("Resolving data map...".to_string());
                        }
                        DownloadEvent::MapChunkFetched { fetched } => {
                            pb.set_message(format!("Resolving data map... ({fetched} chunks)"));
                        }
                        DownloadEvent::DataMapResolved { total_chunks } => {
                            pb.finish_and_clear();
                            pb = progress::attach(ProgressBar::new(total_chunks as u64));
                            pb.set_style(bar_style.clone());
                            pb.set_message("Downloading");
                            pb.enable_steady_tick(Duration::from_millis(80));
                        }
                        DownloadEvent::ChunksFetched { fetched, total: _ } => {
                            pb.set_position(fetched as u64);
                        }
                    }
                }
                pb.finish_and_clear();
            });

            let chunk_peer_check = if all_peers {
                let peer_count = download_peer_check_count(client, peer_count)?;
                let report = client
                    .file_download_with_peer_report_from_closest_peers(
                        &data_map,
                        &output_path,
                        Some(tx),
                        peer_count,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("Download failed: {e}"))?;
                Some(file_peer_check_from_reports(report.chunk_reports))
            } else {
                let download_result = if let Some(diagnostics) = diagnostics.clone() {
                    let peer_count = download_peer_check_count(client, peer_count)?;
                    client
                        .file_download_with_progress_and_diagnostics_from_closest_peers(
                            &data_map,
                            &output_path,
                            Some(tx),
                            peer_count,
                            Some(diagnostics),
                        )
                        .await
                } else if let Some(peer_count) = peer_count {
                    client
                        .file_download_with_progress_from_closest_peers(
                            &data_map,
                            &output_path,
                            Some(tx),
                            peer_count,
                        )
                        .await
                } else {
                    client
                        .file_download_with_progress(&data_map, &output_path, Some(tx))
                        .await
                };
                download_result.map_err(|e| anyhow::anyhow!("Download failed: {e}"))?;
                None
            };

            // Wait for progress bar cleanup (sender dropped → receiver exits)
            let _ = progress_handle.await;

            chunk_peer_check
        };

        Ok(chunk_peer_check)
    }
    .await;

    drop(diagnostics);
    if let Some(writer) = diagnostics_writer {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("Download diagnostics writer thread panicked"))?;
    }

    let chunk_peer_check = download_result?;
    let file_size = std::fs::metadata(&output_path)?.len();
    let elapsed = start.elapsed();

    if json_output {
        let out = DownloadJsonResult {
            file: output_path.display().to_string(),
            size: file_size,
            elapsed_secs: elapsed.as_secs_f64(),
            chunk_peer_check,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("Download complete!");
        println!("  File: {}", output_path.display());
        println!("  Size: {}", format_size(file_size));
        println!("  Time: {:.1}s", elapsed.as_secs_f64());

        if let Some(ref chunk_peer_check) = chunk_peer_check {
            print_file_peer_check(chunk_peer_check);
        }
    }

    Ok(())
}

/// Why a data map couldn't be fetched by address, with what to do about a
/// private file's envelope.
fn data_map_fetch_error(error: DataError) -> anyhow::Error {
    match error {
        DataError::DataMapWithheld(_) => anyhow::anyhow!(
            "This address is a private file's envelope: it stores only a salted hash of the \
             data map, so the file can't be read from the address. Download it with \
             --datamap <FILE>.datamap, or with --proof <FILE> if the uploader revealed it \
             (`darwin file prove`)."
        ),
        error => anyhow::anyhow!("Failed to fetch public DataMap: {error}"),
    }
}

/// Downloading with `--datamap` and an address: if the upload's record is
/// next to the data map, check that the data map is the one the envelope at
/// that address was made from. Returns a note when it can't tell; errors when
/// the data map is not the envelope's.
fn check_datamap_for_address(
    datamap_path: &Path,
    address: &[u8; 32],
    map: &ant_core::data::DataMap,
) -> anyhow::Result<Option<String>> {
    let record_path = record_path_for(datamap_path);
    if !record_path.exists() {
        return Ok(None);
    }
    let record = match read_record(&record_path) {
        Ok(record) => record,
        Err(e) => {
            return Ok(Some(format!(
                "could not read {} to check the data map: {e}",
                record_path.display()
            )))
        }
    };
    let envelope = match ant_core::ant_listings::Envelope::from_bytes(&record.envelope) {
        Ok(envelope) if envelope.address() == *address => envelope,
        _ => {
            return Ok(Some(format!(
                "{} is not for the address given, so the data map can't be checked \
                 against it; using the data map",
                record_path.display()
            )))
        }
    };
    let bytes = ant_core::ant_listings::encode_data_map(map)
        .map_err(|e| anyhow::anyhow!("The data map is invalid: {e}"))?;
    let matches = match (envelope.data_map_bytes(), &record.salt) {
        (Some(own), _) => own == bytes.as_slice(),
        (None, Some(salt)) => envelope.check_reveal(&bytes, salt).is_ok(),
        (None, None) => return Ok(None),
    };
    if !matches {
        anyhow::bail!(
            "{} is not the data map of the envelope at this address",
            datamap_path.display()
        );
    }
    Ok(None)
}

/// Whether `a` and `b` name the same file, following links and relative
/// paths; `b` need not exist yet.
fn same_file(a: &Path, b: &Path) -> bool {
    let resolve = |path: &Path| -> Option<PathBuf> {
        std::fs::canonicalize(path).ok().or_else(|| {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            Some(std::fs::canonicalize(parent).ok()?.join(path.file_name()?))
        })
    };
    matches!((resolve(a), resolve(b)), (Some(a), Some(b)) if a == b)
}

/// `darwin file prove`: write a proof from an upload's record.
fn handle_file_prove(
    record_path: &Path,
    output: Option<PathBuf>,
    no_reveal: bool,
    force: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    let mut proof =
        read_record(record_path).map_err(|e| anyhow::anyhow!("Failed to read the record: {e}"))?;
    let envelope = ant_core::ant_listings::Envelope::from_bytes(&proof.envelope)
        .map_err(|e| anyhow::anyhow!("The record's envelope is invalid: {e}"))?;
    if envelope.address() != proof.address {
        anyhow::bail!("The record's envelope does not hash to its address");
    }
    let private = envelope.is_withheld();
    if no_reveal {
        proof.data_map = None;
        proof.salt = None;
    } else if private {
        // A reveal that doesn't match would make the proof fail later.
        proof_data_map(&proof)
            .map_err(|e| anyhow::anyhow!("The record can't reveal the file: {e}"))?;
    }
    let reveals = private && proof.data_map.is_some();
    let output = output.unwrap_or_else(|| default_proof_path(record_path));
    if same_file(record_path, &output) {
        anyhow::bail!(
            "The proof would replace its record {}, which holds the salt nothing else keeps: \
             choose another --output",
            record_path.display()
        );
    }
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists: pass --force to replace it",
            output.display()
        );
    }
    write_record(&output, &proof).map_err(|e| anyhow::anyhow!("Failed to write the proof: {e}"))?;

    if json_output {
        let out = ProveJson {
            proof: output.display().to_string(),
            address: hex::encode(proof.address),
            private,
            reveals,
        };
        println!("{}", serde_json::to_string(&out)?);
        return Ok(());
    }
    println!("Proof written: {}", output.display());
    println!("  Address: {}", hex::encode(proof.address));
    if reveals {
        println!("  It reveals the data map and salt: anyone with the proof can read the file,");
        println!("  and can check that the envelope is for it.");
    } else if private {
        println!("  It doesn't reveal the data map: it proves the envelope was paid for,");
        println!("  not which file it is for.");
    }
    println!("Anyone can check it from the payment chain with:");
    println!("  darwin file verify {}", output.display());
    Ok(())
}

/// Where `darwin file prove` writes by default: `notes.txt.record` gives
/// `notes.txt.proof`.
fn default_proof_path(record: &Path) -> PathBuf {
    let name = record
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name
        .strip_suffix(&format!(".{}", ant_core::datamap_file::RECORD_EXTENSION))
        .unwrap_or(&name);
    record.with_file_name(format!("{stem}.proof"))
}

/// `darwin file verify`: check a proof from the chain, and optionally a file.
async fn handle_file_verify(
    chain: &ListingChain,
    proof_path: &Path,
    file: Option<&Path>,
    json_output: bool,
) -> anyhow::Result<()> {
    let proof: EnvelopeProof =
        read_record(proof_path).map_err(|e| anyhow::anyhow!("Failed to read the proof: {e}"))?;
    let proven = chain
        .check_proof(&proof)
        .await
        .map_err(|e| anyhow::anyhow!("The proof does not check out: {e}"))?;
    let file_matches = match file {
        None => None,
        Some(path) => {
            let unrevealed = || {
                anyhow::anyhow!(
                    "The proof checks out, but it doesn't reveal the data map, \
                     so it can't be compared with {}",
                    path.display()
                )
            };
            // Said before the file is encrypted, which can take a while.
            if proven.data_map.is_none() {
                return Err(unrevealed());
            }
            let local = file_data_map(path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to encrypt {}: {e}", path.display()))?;
            Some(file_matches(&local, proven.data_map.as_ref()).map_err(|_| unrevealed())?)
        }
    };
    let flags = proven.envelope.flags();
    let metadata = proven.envelope.metadata();
    let quote_hash = ant_core::data::paid_quote_hash(&proven.payment.quote).map(hex::encode);

    if json_output {
        let out = VerifyJson {
            valid: file_matches != Some(false),
            address: hex::encode(proven.address),
            readable: !flags.withheld,
            in_index: flags.in_index,
            hidden: flags.shown.hidden().map(PaymentField::name).collect(),
            name: metadata.name.clone(),
            content_type: metadata.content_type.clone(),
            size: proven.envelope.file_size(),
            revealed: proven.data_map.is_some() && flags.withheld,
            tx_hash: format!("0x{}", hex::encode(proven.payment.tx_hash)),
            block_number: proven.payment.block_number,
            block_timestamp: proven.payment.block_timestamp,
            log_index: proven.payment.log_index,
            quote_hash,
            file_matches,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("The proof checks out against the payment chain.");
        println!("  Address:  {}", hex::encode(proven.address));
        println!(
            "  Envelope: {}, {}",
            if flags.withheld {
                "private (data map withheld)"
            } else {
                "readable"
            },
            if flags.in_index {
                "in the index"
            } else {
                "not in the index"
            }
        );
        if let Some(name) = &metadata.name {
            println!("  Name:     {name}");
        }
        if let Some(content_type) = &metadata.content_type {
            println!("  Type:     {content_type}");
        }
        println!(
            "  Paid:     block {}, log {}, at {} UTC",
            proven.payment.block_number,
            proven.payment.log_index,
            super::listings::utc(proven.payment.block_timestamp)
        );
        println!("  Tx:       0x{}", hex::encode(proven.payment.tx_hash));
        if let Some(quote_hash) = &quote_hash {
            println!("  Quote:    0x{quote_hash}");
        }
        match (flags.withheld, proven.data_map.is_some()) {
            (true, true) => println!("  Reveal:   the data map and salt match the envelope"),
            (true, false) => println!("  Reveal:   none: the proof doesn't say which file this is"),
            (false, _) => {}
        }
        match file_matches {
            Some(true) => println!("  File:     matches the proof's data map"),
            Some(false) => println!("  File:     DOES NOT match the proof's data map"),
            None => {}
        }
        println!();
        println!(
            "This shows the address was paid for by block {}. It doesn't show who uploaded",
            proven.payment.block_number
        );
        println!("the file: a node asked to quote, or anyone who has the envelope, can pay for");
        println!("the same address. Only a revealed data map and salt tie a private envelope to");
        println!("its file.");
    }
    if file_matches == Some(false) {
        anyhow::bail!(
            "{} is not the file this proof is for",
            file.map(|p| p.display().to_string()).unwrap_or_default()
        );
    }
    Ok(())
}

/// Whether a local file, whose data map is `local` ([`file_data_map`]), is
/// the file a proof is for: its data map is the one the proof gives
/// (`proven`: the envelope's own, or the revealed one), byte for byte as the
/// envelope stores it. Self-encryption is deterministic, so the same file
/// always gives the same data map.
///
/// # Errors
///
/// Returns an error when the proof gives no data map: a private file's proof
/// that doesn't reveal it, which can't be compared with anything.
fn file_matches(
    local: &ant_core::data::DataMap,
    proven: Option<&ant_core::data::DataMap>,
) -> anyhow::Result<bool> {
    let proven = proven.ok_or_else(|| anyhow::anyhow!("the proof doesn't reveal the data map"))?;
    let encode = |map| ant_core::ant_listings::encode_data_map(map).ok();
    let local = encode(local);
    Ok(local.is_some() && local == encode(proven))
}

#[derive(Serialize)]
struct ProveJson {
    proof: String,
    address: String,
    private: bool,
    reveals: bool,
}

#[derive(Serialize)]
struct VerifyJson {
    valid: bool,
    address: String,
    readable: bool,
    in_index: bool,
    hidden: Vec<&'static str>,
    name: Option<String>,
    content_type: Option<String>,
    size: Option<u64>,
    revealed: bool,
    tx_hash: String,
    block_number: u64,
    block_timestamp: u64,
    log_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_matches: Option<bool>,
}

async fn handle_file_cost(
    client: &Client,
    path: &Path,
    options: EnvelopeOptions,
    mode: PaymentMode,
    json_output: bool,
    token: &str,
) -> anyhow::Result<()> {
    let file_size = std::fs::metadata(path)?.len();
    let envelope = options.needs_envelope();
    let readable = options.readable;
    let visibility = options.into_visibility();

    let raw_result = if json_output {
        client
            .estimate_upload_cost_with_visibility(path, mode, visibility, None)
            .await
    } else {
        let (tx, rx) = mpsc::channel(64);
        let pb_handle = tokio::spawn(drive_upload_progress(
            rx,
            path.display().to_string(),
            file_size,
        ));

        let result = client
            .estimate_upload_cost_with_visibility(path, mode, visibility, Some(tx))
            .await;
        let _ = pb_handle.await;
        result
    };

    let estimate = raw_result.map_err(|e| anyhow::anyhow!("Cost estimation failed: {e}"))?;

    if json_output {
        println!("{}", serde_json::to_string(&estimate)?);
    } else {
        let cost_display = cost_text(
            estimate.confidence,
            &estimate.storage_cost_atto,
            &estimate.estimated_gas_cost_wei,
            token,
        );

        println!();
        println!("Estimated upload cost for {}", path.display());
        println!("  Size:    {}", format_size(estimate.file_size));
        println!(
            "  Chunks:  {}",
            chunks_summary(
                estimate.chunk_count,
                estimate.chunk_count,
                envelope,
                readable
            )
        );
        println!("  Cost:    {cost_display}");
    }

    Ok(())
}

/// How `darwin file cost` shows an estimate. The estimate is display-only; the
/// real upload reconciles the true cost at payment time. When every sampled
/// chunk is already stored we say so rather than print a misleading priced
/// number: free, or the price of the one chunk the upload adds (its envelope
/// or data map) when only that was quoted.
fn cost_text(
    confidence: CostEstimateConfidence,
    storage_cost_atto: &str,
    gas_cost_wei: &str,
    token: &str,
) -> String {
    let gas_wei: u128 = gas_cost_wei.parse().unwrap_or(0);
    let priced = storage_cost_atto.parse::<u128>().unwrap_or(0) != 0;
    match confidence {
        CostEstimateConfidence::VerifiedAllAlreadyStored => {
            "already stored on the network — free".to_string()
        }
        CostEstimateConfidence::AllSamplesAlreadyStoredIncomplete if priced => format!(
            "{} for the envelope or data map; the content is likely already stored \
             (confirmed at payment)",
            format_cost(storage_cost_atto, gas_wei, token)
        ),
        CostEstimateConfidence::AllSamplesAlreadyStoredIncomplete => {
            "likely already stored — free (confirmed at payment)".to_string()
        }
        CostEstimateConfidence::PricedSample => format_cost(storage_cost_atto, gas_wei, token),
    }
}

#[derive(Serialize)]
struct UploadJsonResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    datamap: Option<String>,
    mode: String,
    chunks: usize,
    total_chunks: usize,
    chunks_stored: usize,
    chunks_failed: usize,
    size: u64,
    storage_cost_atto: String,
    gas_cost_wei: String,
    elapsed_secs: f64,
    /// Sum of chunk-store RPC attempts; `>= chunks_stored` on success.
    chunk_attempts_total: usize,
    /// Per-chunk store wall-clock in ms. Empty for upload paths that
    /// don't run the wave store loop.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    store_durations_ms: Vec<u64>,
    /// Stored-chunk count by retry round (index 0 = first attempt).
    retries_histogram: [usize; 4],
    /// The upload's choices, envelope and record.
    #[serde(flatten)]
    choices: UploadChoicesJson,
}

/// The fields an upload's JSON has for its choices, envelope and record.
#[derive(Serialize)]
struct UploadChoicesJson {
    /// Whether anyone with the address can read the file.
    readable: bool,
    /// Whether the file is in the listings index.
    in_index: bool,
    /// The payment fields hidden: `tx-hash`, `block`, `timestamp`,
    /// `log-index`, `quote`.
    hidden: Vec<&'static str>,
    /// The envelope's address, for an upload with an envelope (for a readable
    /// one, the same as `address`).
    #[serde(skip_serializing_if = "Option::is_none")]
    envelope_address: Option<String>,
    /// The saved record: envelope, payment, and a private file's data map
    /// and salt.
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<String>,
    /// Whether the record was checked against the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    record_checked: Option<bool>,
    /// Why there is no record, why it wasn't saved, or why it wasn't checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    record_problem: Option<String>,
    /// What the upload's choices give away (also printed to stderr).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct UploadFailureJson<'a> {
    error: &'a str,
    total_chunks: usize,
    chunks_stored: usize,
    chunks_failed: usize,
    /// Storage cost paid on-chain so far, in atto-tokens. A partial upload
    /// still spends money for the chunks it paid for.
    storage_cost_atto: String,
    /// Gas cost paid on-chain so far, in wei.
    gas_cost_wei: String,
    reason: &'a str,
}

#[derive(Serialize)]
struct DownloadJsonResult {
    file: String,
    size: u64,
    elapsed_secs: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunk_peer_check: Option<FilePeerCheckJson>,
}

#[derive(Serialize)]
struct FilePeerCheckJson {
    summary: FilePeerCheckSummaryJson,
    chunks: Vec<FileChunkPeerCheckJson>,
}

#[derive(Default, Serialize)]
struct FilePeerCheckSummaryJson {
    chunks: usize,
    sweeps: usize,
    failed_sweeps: usize,
    peers_queried: usize,
    found: usize,
    not_found: usize,
    timeout: usize,
    network_error: usize,
    error: usize,
}

impl FilePeerCheckSummaryJson {
    fn record_chunk(&mut self, summary: &PeerGetSummaryJson) {
        self.peers_queried += summary.peers_queried;
        self.found += summary.found;
        self.not_found += summary.not_found;
        self.timeout += summary.timeout;
        self.network_error += summary.network_error;
        self.error += summary.error;
    }
}

#[derive(Serialize)]
struct FileChunkPeerCheckJson {
    index: usize,
    address: String,
    summary: PeerGetSummaryJson,
    sweeps: Vec<PeerSweepResultJson>,
}

#[derive(Serialize)]
struct PeerSweepResultJson {
    attempt: usize,
    deferred_retry: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    summary: PeerGetSummaryJson,
    peers: Vec<PeerGetResultJson>,
}

#[derive(Default, Serialize)]
struct PeerGetSummaryJson {
    peers_queried: usize,
    found: usize,
    not_found: usize,
    timeout: usize,
    network_error: usize,
    error: usize,
}

impl PeerGetSummaryJson {
    fn record_summary(&mut self, summary: &PeerGetSummaryJson) {
        self.peers_queried += summary.peers_queried;
        self.found += summary.found;
        self.not_found += summary.not_found;
        self.timeout += summary.timeout;
        self.network_error += summary.network_error;
        self.error += summary.error;
    }

    fn record_status(&mut self, status: &FileChunkPeerStatus) -> String {
        match status {
            FileChunkPeerStatus::Found { bytes } => {
                self.found += 1;
                format!("found bytes={bytes}")
            }
            FileChunkPeerStatus::NotFound => {
                self.not_found += 1;
                "not_found".to_string()
            }
            FileChunkPeerStatus::Timeout { message } => {
                self.timeout += 1;
                format!("timeout message={message}")
            }
            FileChunkPeerStatus::NetworkError { message } => {
                self.network_error += 1;
                format!("network_error message={message}")
            }
            FileChunkPeerStatus::Error { message } => {
                self.error += 1;
                format!("error message={message}")
            }
        }
    }
}

#[derive(Serialize)]
struct PeerGetResultJson {
    rank: usize,
    peer: String,
    distance: String,
    addrs: usize,
    result: String,
}

fn download_peer_check_count(
    client: &Client,
    peer_count: Option<NonZeroUsize>,
) -> anyhow::Result<NonZeroUsize> {
    if let Some(peer_count) = peer_count {
        return Ok(peer_count);
    }

    NonZeroUsize::new(client.config().close_group_size)
        .ok_or_else(|| anyhow::anyhow!("Client close group size must be greater than 0"))
}

fn file_peer_check_from_reports(reports: Vec<FileChunkPeerReport>) -> FilePeerCheckJson {
    let mut summary = FilePeerCheckSummaryJson {
        chunks: reports.len(),
        ..FilePeerCheckSummaryJson::default()
    };
    let chunks = reports
        .iter()
        .map(|report| {
            let chunk = file_chunk_peer_report(report);
            summary.sweeps += chunk.sweeps.len();
            summary.failed_sweeps += chunk
                .sweeps
                .iter()
                .filter(|sweep| peer_sweep_failed(sweep))
                .count();
            summary.record_chunk(&chunk.summary);
            chunk
        })
        .collect();

    FilePeerCheckJson { summary, chunks }
}

fn file_chunk_peer_report(report: &FileChunkPeerReport) -> FileChunkPeerCheckJson {
    let mut summary = PeerGetSummaryJson::default();
    let sweeps = report
        .sweeps
        .iter()
        .map(|sweep| {
            let sweep = file_chunk_peer_sweep_report(sweep);
            summary.record_summary(&sweep.summary);
            sweep
        })
        .collect();

    FileChunkPeerCheckJson {
        index: report.index,
        address: hex::encode(report.address),
        summary,
        sweeps,
    }
}

fn file_chunk_peer_sweep_report(sweep: &FileChunkPeerSweepReport) -> PeerSweepResultJson {
    let mut summary = PeerGetSummaryJson {
        peers_queried: sweep.peers.len(),
        ..PeerGetSummaryJson::default()
    };
    if sweep.error.is_some() {
        summary.error += 1;
    }
    let peers = sweep
        .peers
        .iter()
        .enumerate()
        .map(|(peer_index, peer)| peer_get_result_json(peer_index, peer, &mut summary))
        .collect();

    PeerSweepResultJson {
        attempt: sweep.attempt,
        deferred_retry: sweep.deferred_retry,
        error: sweep.error.clone(),
        summary,
        peers,
    }
}

fn peer_get_result_json(
    peer_index: usize,
    peer: &FileChunkPeerReportPeer,
    summary: &mut PeerGetSummaryJson,
) -> PeerGetResultJson {
    PeerGetResultJson {
        rank: peer_index + 1,
        peer: peer.peer_id.to_string(),
        distance: xor_distance_decimal(&peer.xor_distance),
        addrs: peer.peer_addrs.len(),
        result: summary.record_status(&peer.status),
    }
}

fn peer_sweep_failed(sweep: &PeerSweepResultJson) -> bool {
    sweep.error.is_some() || sweep.summary.found == 0
}

fn print_file_peer_check(report: &FilePeerCheckJson) {
    let total_chunks = report.summary.chunks;
    println!();
    println!("Closest peer GET results for {total_chunks} file chunk(s):");

    for chunk in &report.chunks {
        println!();
        println!("Chunk {}/{}:", chunk.index, total_chunks);
        for sweep in &chunk.sweeps {
            println!();
            let attempt = sweep.attempt;
            if sweep.deferred_retry {
                println!("Attempt {attempt} (deferred retry):");
            } else {
                println!("Attempt {attempt}:");
            }
            if let Some(error) = &sweep.error {
                println!("Sweep error: {error}");
            }
            println!("Closest peer GET results for {}:", chunk.address);
            for peer in &sweep.peers {
                let rank = peer.rank;
                let peer_id = &peer.peer;
                let distance = &peer.distance;
                let addr_count = peer.addrs;
                let status = &peer.result;
                println!(
                    "{rank}. peer={peer_id} distance={distance} addrs={addr_count} result={status}"
                );
            }
            print_peer_get_summary(&sweep.summary);
        }
        println!("Chunk aggregate:");
        print_peer_get_summary(&chunk.summary);
    }

    println!();
    print_file_peer_check_summary(&report.summary);
}

fn print_peer_get_summary(summary: &PeerGetSummaryJson) {
    let found = summary.found;
    let not_found = summary.not_found;
    let timeout = summary.timeout;
    let network_error = summary.network_error;
    let error = summary.error;
    println!(
        "Summary: found={found} not_found={not_found} timeout={timeout} network_error={network_error} error={error}",
    );
}

fn print_file_peer_check_summary(summary: &FilePeerCheckSummaryJson) {
    let chunks = summary.chunks;
    let sweeps = summary.sweeps;
    let failed_sweeps = summary.failed_sweeps;
    let peers_queried = summary.peers_queried;
    let found = summary.found;
    let not_found = summary.not_found;
    let timeout = summary.timeout;
    let network_error = summary.network_error;
    let error = summary.error;
    println!(
        "File chunk peer check summary: chunks={chunks} sweeps={sweeps} failed_sweeps={failed_sweeps} peers_queried={peers_queried} found={found} not_found={not_found} timeout={timeout} network_error={network_error} error={error}",
    );
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format storage cost for human display, in the payment token `token`
/// (its symbol, from `ant_core::config::token_symbol`).
///
/// Always shows the most readable denomination:
/// - >= 1 token (1e18 atto): "1.25 TEST"
/// - >= 0.001 token: "0.2500 TEST"
/// - < 0.001 token: "X nanoTEST"
/// - 0: "free"
fn format_storage_cost(atto_str: &str, token: &str) -> String {
    let atto: u128 = atto_str.parse().unwrap_or(0);
    if atto == 0 {
        return "free".to_string();
    }
    let whole = atto as f64 / 1e18;
    if whole >= 1.0 {
        format!("{whole:.2} {token}")
    } else if whole >= 0.001 {
        format!("{whole:.4} {token}")
    } else {
        let nano = atto as f64 / 1e9;
        format!("{nano:.2} nano{token}")
    }
}

/// Format gas cost as ETH.
fn format_gas_cost(wei: u128) -> String {
    if wei == 0 {
        return "free".to_string();
    }
    let eth = wei as f64 / 1e18;
    if eth >= 0.01 {
        format!("{eth:.4} ETH")
    } else {
        format!("{eth:.6} ETH")
    }
}

/// Combined cost display, the storage cost in the payment token `token`.
fn format_cost(storage_cost_atto: &str, gas_cost_wei: u128, token: &str) -> String {
    let atto: u128 = storage_cost_atto.parse().unwrap_or(0);
    if atto == 0 && gas_cost_wei == 0 {
        return "free (already stored)".to_string();
    }
    let storage = format_storage_cost(storage_cost_atto, token);
    let gas = format_gas_cost(gas_cost_wei);
    format!("{storage} (gas: {gas})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_core::data::Visibility;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestFileCli {
        #[command(subcommand)]
        action: FileAction,
    }

    const TEST_ADDRESS_BYTE_LEN: usize = 32;
    const PUBLIC_DOWNLOAD_PEERS: usize = 12;
    const PRIVATE_DOWNLOAD_PEERS: usize = 9;
    const DIAGNOSTIC_DOWNLOAD_PEERS: usize = 5;

    fn test_address() -> String {
        "00".repeat(TEST_ADDRESS_BYTE_LEN)
    }

    #[test]
    fn resolve_download_output_returns_explicit_output_unchanged() {
        let explicit = PathBuf::from("custom/path.bin");
        let datamap = PathBuf::from("photo.jpg.datamap");
        let resolved =
            resolve_download_output(Some(explicit.clone()), Some(datamap.as_path())).unwrap();
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn resolve_download_output_explicit_wins_even_without_datamap() {
        let explicit = PathBuf::from("out.bin");
        let resolved = resolve_download_output(Some(explicit.clone()), None).unwrap();
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn resolve_download_output_derives_from_datamap_basename() {
        let datamap = PathBuf::from("photo.jpg.datamap");
        let resolved = resolve_download_output(None, Some(datamap.as_path())).unwrap();
        assert_eq!(resolved, PathBuf::from("photo.jpg"));
    }

    #[test]
    fn resolve_download_output_derives_from_full_datamap_path() {
        let datamap = PathBuf::from("/tmp/sub/archive.tar.gz.datamap");
        let resolved = resolve_download_output(None, Some(datamap.as_path())).unwrap();
        assert_eq!(resolved, PathBuf::from("archive.tar.gz"));
    }

    #[test]
    fn resolve_download_output_errors_on_address_download_without_output() {
        let err = resolve_download_output(None, None).unwrap_err();
        assert!(
            err.to_string().contains("--output"),
            "expected --output guidance, got: {err}"
        );
    }

    #[test]
    fn resolve_download_output_errors_on_bare_dot_datamap() {
        // `.datamap` strips to an empty stem; we refuse to default-save
        // to "" and instead instruct the user to pass -o.
        let datamap = PathBuf::from(".datamap");
        let err = resolve_download_output(None, Some(datamap.as_path())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Cannot derive"), "got: {msg}");
        assert!(msg.contains("-o/--output"), "got: {msg}");
    }

    #[test]
    fn resolve_download_output_errors_on_non_datamap_extension() {
        let datamap = PathBuf::from("photo.jpg");
        let err = resolve_download_output(None, Some(datamap.as_path())).unwrap_err();
        assert!(err.to_string().contains("Cannot derive"));
    }

    #[test]
    fn download_peers_is_accepted_for_public_download() {
        let address = test_address();
        let peer_count = PUBLIC_DOWNLOAD_PEERS.to_string();
        let cli = TestFileCli::try_parse_from([
            "test",
            "download",
            address.as_str(),
            "--peers",
            peer_count.as_str(),
            "--output",
            "out.bin",
        ])
        .expect("--peers must parse for address downloads");

        match cli.action {
            FileAction::Download { peers, address, .. } => {
                assert!(address.is_some());
                assert_eq!(peers.map(NonZeroUsize::get), Some(PUBLIC_DOWNLOAD_PEERS));
            }
            _ => panic!("expected file download action"),
        }
    }

    #[test]
    fn download_peers_is_accepted_for_private_download() {
        let peer_count = PRIVATE_DOWNLOAD_PEERS.to_string();
        let cli = TestFileCli::try_parse_from([
            "test",
            "download",
            "--datamap",
            "photo.jpg.datamap",
            "--peers",
            peer_count.as_str(),
        ])
        .expect("--peers must parse for datamap downloads");

        match cli.action {
            FileAction::Download { peers, datamap, .. } => {
                assert!(datamap.is_some());
                assert_eq!(peers.map(NonZeroUsize::get), Some(PRIVATE_DOWNLOAD_PEERS));
            }
            _ => panic!("expected file download action"),
        }
    }

    #[test]
    fn download_peers_rejects_zero() {
        let address = test_address();
        let err = TestFileCli::try_parse_from([
            "test",
            "download",
            address.as_str(),
            "--peers",
            "0",
            "--output",
            "out.bin",
        ])
        .expect_err("--peers=0 must fail");

        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn download_all_peers_is_accepted() {
        let address = test_address();
        let cli = TestFileCli::try_parse_from([
            "test",
            "download",
            address.as_str(),
            "--all-peers",
            "--output",
            "out.bin",
        ])
        .expect("--all-peers must parse for file downloads");

        match cli.action {
            FileAction::Download { all_peers, .. } => assert!(all_peers),
            _ => panic!("expected file download action"),
        }
    }

    #[test]
    fn download_try_all_peers_alias_is_accepted_with_peer_count_alias() {
        let address = test_address();
        let peer_count = DIAGNOSTIC_DOWNLOAD_PEERS.to_string();
        let cli = TestFileCli::try_parse_from([
            "test",
            "download",
            address.as_str(),
            "--try-all-peers",
            "--peer-count",
            peer_count.as_str(),
            "--output",
            "out.bin",
        ])
        .expect("--try-all-peers and --peer-count must parse for file downloads");

        match cli.action {
            FileAction::Download {
                all_peers, peers, ..
            } => {
                assert!(all_peers);
                assert_eq!(
                    peers.map(NonZeroUsize::get),
                    Some(DIAGNOSTIC_DOWNLOAD_PEERS)
                );
            }
            _ => panic!("expected file download action"),
        }
    }

    fn upload(args: &[&str]) -> Result<EnvelopeOptions, String> {
        let mut argv = vec!["test", "upload", "notes.txt"];
        argv.extend_from_slice(args);
        let cli = TestFileCli::try_parse_from(argv).map_err(|e| e.to_string())?;
        match cli.action {
            FileAction::Upload { choices, .. } => choices.options().map_err(|e| e.to_string()),
            _ => panic!("expected file upload action"),
        }
    }

    #[test]
    fn upload_defaults_to_private_with_every_field_shown() {
        let options = upload(&[]).unwrap();
        assert_eq!(options, EnvelopeOptions::private());
        assert!(matches!(options.into_visibility(), Visibility::Envelope(_)));
    }

    #[test]
    fn visibility_is_shorthand_for_readable_and_index() {
        assert_eq!(
            upload(&["--visibility", "private"]).unwrap(),
            EnvelopeOptions::private()
        );
        assert_eq!(
            upload(&["--visibility", "unlisted"]).unwrap(),
            EnvelopeOptions::unlisted()
        );
        assert_eq!(
            upload(&["--visibility", "listed"]).unwrap(),
            EnvelopeOptions::listed()
        );
        assert_eq!(upload(&["--public"]).unwrap(), EnvelopeOptions::unlisted());
        assert_eq!(
            upload(&["--readable", "yes"]).unwrap(),
            EnvelopeOptions::unlisted()
        );
        assert_eq!(
            upload(&["--readable", "yes", "--index", "yes"]).unwrap(),
            EnvelopeOptions::listed()
        );
        // The fourth combination: dated and listed, unreadable.
        let dated = upload(&["--index", "yes"]).unwrap();
        assert!(!dated.readable);
        assert!(dated.in_index);
        assert!(upload(&["--readable", "maybe"]).is_err());
        assert!(upload(&["--visibility", "listed", "--readable", "no"]).is_err());
        assert!(upload(&["--public", "--index", "yes"]).is_err());
        assert!(upload(&["--public", "--visibility", "listed"]).is_err());
    }

    #[test]
    fn hide_takes_field_names_and_all() {
        let options = upload(&["--hide", "tx-hash,quote"]).unwrap();
        assert_eq!(
            options.shown,
            ShownFields::ALL
                .without(PaymentField::TxHash)
                .without(PaymentField::Quote)
        );
        let options = upload(&["--hide", "block", "--hide", "log-index"]).unwrap();
        assert_eq!(
            options.shown,
            ShownFields::ALL
                .without(PaymentField::BlockNumber)
                .without(PaymentField::LogIndex)
        );
        assert!(upload(&["--hide", "wallet"]).is_err());
        // Hiding everything on a private, unindexed upload without metadata
        // needs no envelope: it is stored exactly as before.
        let bare = upload(&["--hide", "all"]).unwrap();
        assert_eq!(bare.shown, ShownFields::NONE);
        assert_eq!(bare.into_visibility(), Visibility::Private);
        assert_eq!(
            upload(&["--hide", "all", "--public"])
                .unwrap()
                .into_visibility(),
            Visibility::Public
        );
        assert!(matches!(
            upload(&["--hide", "all", "--name", "notes.txt"])
                .unwrap()
                .into_visibility(),
            Visibility::Envelope(_)
        ));
    }

    #[test]
    fn metadata_works_on_every_visibility_and_is_checked() {
        for visibility in ["private", "unlisted", "listed"] {
            let options = upload(&[
                "--visibility",
                visibility,
                "--name",
                "notes.txt",
                "--content-type",
                "text/plain",
            ])
            .unwrap();
            assert_eq!(options.metadata.name.as_deref(), Some("notes.txt"));
            assert_eq!(options.metadata.content_type.as_deref(), Some("text/plain"));
        }
        assert!(upload(&["--name", "a/b"]).is_err());
        assert!(upload(&["--content-type", "not a type"]).is_err());
    }

    #[test]
    fn upload_modes_keep_their_json_names() {
        assert_eq!(upload_mode(&EnvelopeOptions::private()), "private");
        assert_eq!(upload_mode(&EnvelopeOptions::unlisted()), "public");
        assert_eq!(upload_mode(&EnvelopeOptions::listed()), "listed");
        let dated = EnvelopeOptions {
            in_index: true,
            ..EnvelopeOptions::private()
        };
        assert_eq!(upload_mode(&dated), "private");
    }

    #[test]
    fn prove_and_verify_parse_and_need_no_storage_network() {
        let cli = TestFileCli::try_parse_from(["test", "prove", "notes.txt.record", "--no-reveal"])
            .unwrap();
        assert!(!cli.action.needs_network());
        match cli.action {
            FileAction::Prove {
                record, no_reveal, ..
            } => {
                assert_eq!(record, PathBuf::from("notes.txt.record"));
                assert!(no_reveal);
            }
            _ => panic!("expected prove"),
        }
        let cli = TestFileCli::try_parse_from([
            "test",
            "verify",
            "notes.txt.proof",
            "--file",
            "notes.txt",
        ])
        .unwrap();
        assert!(!cli.action.needs_network());
        let cli = TestFileCli::try_parse_from([
            "test",
            "download",
            "--proof",
            "notes.txt.proof",
            "-o",
            "notes.txt",
        ])
        .unwrap();
        assert!(cli.action.needs_network());
        assert!(TestFileCli::try_parse_from([
            "test",
            "download",
            "--proof",
            "p",
            "--datamap",
            "d.datamap"
        ])
        .is_err());
    }

    /// A private file's data map, salt and record, as an upload saves them.
    fn private_record(salt: [u8; 32]) -> (ant_core::data::DataMap, EnvelopeProof) {
        use ant_core::ant_listings::{encode_data_map, self_encryption, Envelope};
        let (map, _) =
            self_encryption::encrypt(bytes::Bytes::from(vec![7u8; 5_000])).expect("encrypt");
        let envelope =
            Envelope::withheld(&map, &salt, Metadata::default(), ShownFields::ALL, false)
                .expect("envelope");
        let record = EnvelopeProof {
            address: envelope.address(),
            envelope: envelope.to_bytes(),
            tx_hash: [8; 32],
            quote: vec![1, 2, 3],
            data_map: Some(encode_data_map(&map).expect("encode")),
            salt: Some(salt),
        };
        (map, record)
    }

    #[test]
    fn prove_reveals_or_strips_the_data_map_and_salt() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("notes.txt.record");
        let (_, record) = private_record([4; 32]);
        write_record(&record_path, &record).unwrap();

        // By default the proof reveals the data map and salt.
        handle_file_prove(&record_path, None, false, false, true).unwrap();
        let proof = read_record(&dir.path().join("notes.txt.proof")).unwrap();
        assert_eq!(proof, record);

        // --no-reveal proves only the payment.
        let bare = dir.path().join("bare.proof");
        handle_file_prove(&record_path, Some(bare.clone()), true, false, true).unwrap();
        let proof = read_record(&bare).unwrap();
        assert_eq!((proof.data_map, proof.salt), (None, None));
        assert_eq!(proof.envelope, record.envelope);

        // An existing proof is replaced only with --force.
        let error = handle_file_prove(&record_path, Some(bare.clone()), false, false, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--force"), "{error}");
        assert_eq!(read_record(&bare).unwrap().salt, None);
        handle_file_prove(&record_path, Some(bare.clone()), false, true, true).unwrap();
        assert_eq!(read_record(&bare).unwrap().salt, Some([4; 32]));

        // The record itself is never replaced, even with --force, under any
        // spelling of its path.
        for output in [
            record_path.clone(),
            dir.path().join(".").join("notes.txt.record"),
        ] {
            let error = handle_file_prove(&record_path, Some(output), true, true, true)
                .unwrap_err()
                .to_string();
            assert!(error.contains("replace its record"), "{error}");
        }
        assert_eq!(read_record(&record_path).unwrap(), record);
    }

    #[test]
    fn prove_refuses_a_record_that_does_not_check_out() {
        let dir = tempfile::tempdir().unwrap();
        let (_, record) = private_record([4; 32]);
        // A damaged salt: the reveal no longer matches the envelope.
        let damaged = dir.path().join("salt.record");
        write_record(
            &damaged,
            &EnvelopeProof {
                salt: Some([5; 32]),
                ..record.clone()
            },
        )
        .unwrap();
        let error = handle_file_prove(&damaged, None, false, false, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("can't reveal"), "{error}");
        assert!(!dir.path().join("salt.proof").exists());
        // An envelope that doesn't hash to the record's address.
        let moved = dir.path().join("address.record");
        write_record(
            &moved,
            &EnvelopeProof {
                address: [0; 32],
                ..record
            },
        )
        .unwrap();
        let error = handle_file_prove(&moved, None, true, false, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not hash"), "{error}");
    }

    #[test]
    fn a_datamap_given_with_an_address_is_checked_against_its_record() {
        let dir = tempfile::tempdir().unwrap();
        let datamap = dir.path().join("notes.txt.datamap");
        let (map, record) = private_record([4; 32]);
        let (_, other) = private_record([6; 32]);
        let (other_map, _) = {
            use ant_core::ant_listings::self_encryption;
            self_encryption::encrypt(bytes::Bytes::from(vec![9u8; 5_000])).unwrap()
        };
        // No record next to it: nothing to check.
        assert_eq!(
            check_datamap_for_address(&datamap, &record.address, &map).unwrap(),
            None
        );
        write_record(&record_path_for(&datamap), &record).unwrap();
        // The data map the envelope was made from.
        assert_eq!(
            check_datamap_for_address(&datamap, &record.address, &map).unwrap(),
            None
        );
        // Another data map is refused.
        assert!(check_datamap_for_address(&datamap, &record.address, &other_map).is_err());
        // A record for another address can't check it: a note, not an error.
        let note = check_datamap_for_address(&datamap, &other.address, &map)
            .unwrap()
            .expect("a note");
        assert!(note.contains("not for the address given"), "{note}");
    }

    #[test]
    fn download_takes_a_datamap_with_an_envelope_address() {
        let cli = TestFileCli::try_parse_from([
            "test",
            "download",
            &test_address(),
            "--datamap",
            "notes.txt.datamap",
        ])
        .unwrap();
        match cli.action {
            FileAction::Download {
                address, datamap, ..
            } => {
                assert!(address.is_some());
                assert_eq!(datamap, Some(PathBuf::from("notes.txt.datamap")));
            }
            _ => panic!("expected download"),
        }
    }

    #[test]
    fn cost_takes_the_upload_choices() {
        let cost = |args: &[&str]| {
            let mut argv = vec!["test", "cost", "notes.txt"];
            argv.extend_from_slice(args);
            match TestFileCli::try_parse_from(argv).unwrap().action {
                FileAction::Cost { choices, .. } => choices.options().unwrap(),
                _ => panic!("expected cost"),
            }
        };
        assert_eq!(cost(&[]), EnvelopeOptions::private());
        assert!(cost(&[]).needs_envelope());
        assert_eq!(cost(&["--visibility", "listed"]), EnvelopeOptions::listed());
        assert!(!cost(&["--hide", "all"]).needs_envelope());
        assert!(
            TestFileCli::try_parse_from(["test", "cost", "f", "--public", "--index", "yes"])
                .is_err()
        );
    }

    #[test]
    fn the_summary_counts_the_envelope_or_data_map_once() {
        // A 3-chunk private file and its envelope: 4 stored.
        assert_eq!(chunks_summary(4, 4, true, false), "4 (3 + 1 envelope)");
        assert_eq!(chunks_summary(4, 4, true, true), "4 (3 + 1 envelope)");
        // A plain public upload, as before envelopes.
        assert_eq!(chunks_summary(7, 7, false, true), "7 (6 + 1 data map)");
        assert_eq!(chunks_summary(3, 3, false, false), "3");
    }

    #[test]
    fn the_private_envelope_note_follows_what_is_shown() {
        assert_eq!(
            private_envelope_note(&EnvelopeOptions::private()),
            "its payment record is public, the file is not"
        );
        let hidden = EnvelopeOptions {
            shown: ShownFields::NONE,
            ..EnvelopeOptions::private()
        };
        let named = hidden.clone().with_metadata(Metadata {
            content_type: Some("text/plain".into()),
            name: Some("notes.txt".into()),
        });
        assert_eq!(
            private_envelope_note(&named),
            "its name and content type are public; the payment and the file are not"
        );
        let dated = EnvelopeOptions {
            in_index: true,
            ..hidden
        };
        assert_eq!(
            private_envelope_note(&dated),
            "its listing is public; the payment and the file are not"
        );
    }

    #[test]
    fn upload_json_carries_the_choices_and_the_record() {
        let json = |options: &EnvelopeOptions,
                    envelope: Option<(String, bool)>,
                    record: Option<&Path>,
                    problem: Option<String>| {
            let warnings = options.warnings().iter().map(ToString::to_string).collect();
            serde_json::to_value(upload_choices_json(
                options, envelope, record, problem, warnings,
            ))
            .unwrap()
        };
        let address = "ab".repeat(32);

        // Private, with an envelope and a saved, checked record.
        let private = json(
            &EnvelopeOptions::private(),
            Some((address.clone(), true)),
            Some(Path::new("notes.txt.record")),
            None,
        );
        assert_eq!(private["readable"], false);
        assert_eq!(private["in_index"], false);
        assert_eq!(private["hidden"], serde_json::json!([]));
        assert_eq!(private["envelope_address"], address.as_str());
        assert_eq!(private["record"], "notes.txt.record");
        assert_eq!(private["record_checked"], true);
        assert!(private.get("record_problem").is_none());
        assert!(!private["warnings"].as_array().unwrap().is_empty());

        // Unlisted, whose record couldn't be saved.
        let unlisted = json(
            &EnvelopeOptions::unlisted().hiding([PaymentField::Quote]),
            Some((address.clone(), false)),
            None,
            join_problems(
                Some("the record could not be saved: read-only".into()),
                Some("not checked".into()),
            ),
        );
        assert_eq!(unlisted["readable"], true);
        assert_eq!(unlisted["hidden"], serde_json::json!(["quote"]));
        assert!(unlisted.get("record").is_none());
        assert_eq!(unlisted["record_checked"], false);
        assert_eq!(
            unlisted["record_problem"],
            "the record could not be saved: read-only; not checked"
        );

        // Everything hidden on a plain private upload: no envelope at all.
        let bare = EnvelopeOptions {
            shown: ShownFields::NONE,
            ..EnvelopeOptions::private()
        };
        let bare = json(&bare, None, None, None);
        let keys: Vec<&str> = bare
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["hidden", "in_index", "readable"]);
        assert_eq!(bare["hidden"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn bad_choices_are_refused_before_the_wallet_or_the_network() {
        let action = |argv: &[&str]| TestFileCli::try_parse_from(argv).unwrap().action;
        // `main` calls `validate` before it asks for SECRET_KEY or connects.
        let error = action(&["test", "upload", "f.txt", "--hide", "tx_hash"])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(error.contains("tx_hash"), "{error}");
        assert!(action(&["test", "upload", "f.txt", "--name", "a/b"])
            .validate()
            .is_err());
        assert!(
            action(&["test", "upload", "f.txt", "--content-type", "nonsense"])
                .validate()
                .is_err()
        );
        assert!(action(&["test", "cost", "f.txt", "--hide", "foo"])
            .validate()
            .is_err());
        assert!(
            action(&["test", "upload", "f.txt", "--hide", "tx-hash,quote"])
                .validate()
                .is_ok()
        );
        assert!(action(&["test", "cost", "f.txt", "--visibility", "listed"])
            .validate()
            .is_ok());
        assert!(action(&["test", "prove", "f.txt.record"])
            .validate()
            .is_ok());
    }

    #[test]
    fn the_record_note_says_whether_the_record_is_saved() {
        let unchecked = "not checked against the chain: no receipt";
        assert_eq!(
            record_note(true, false, Some(unchecked), true).as_deref(),
            Some(
                "the record is saved but was not checked against the chain: no receipt; \
                 check it later with `darwin file verify`"
            )
        );
        // Not saved: it doesn't claim it is, nor point at a file that isn't
        // there.
        let note = record_note(true, false, Some(unchecked), false);
        assert_eq!(
            note.as_deref(),
            Some("the record was not checked against the chain: no receipt")
        );
        let joined = join_problems(
            Some("the record could not be saved: read-only".into()),
            note,
        )
        .unwrap();
        assert!(!joined.contains("is saved"), "{joined}");
        assert!(!joined.contains("darwin file verify"), "{joined}");
        // Checked: nothing to say, saved or not.
        assert_eq!(record_note(true, true, None, true), None);
        assert_eq!(record_note(true, true, None, false), None);
        // No record at all.
        assert_eq!(
            record_note(false, false, Some("already stored"), false).as_deref(),
            Some("no record saved: already stored")
        );
        assert_eq!(
            record_note(false, false, None, false).as_deref(),
            Some("no record saved")
        );
    }

    #[tokio::test]
    async fn verify_compares_a_local_file_with_the_proven_data_map() {
        use ant_core::ant_listings::self_encryption;
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, fill: u8| {
            let path = dir.path().join(name);
            std::fs::write(&path, vec![fill; 5_000]).unwrap();
            path
        };
        let same = write("same.bin", 7);
        let other = write("other.bin", 8);
        // The map `private_record` reveals is for 5,000 bytes of 7s.
        let (proven, record) = private_record([4; 32]);
        // `file_data_map` gives the same map as encrypting the bytes in
        // memory, as an upload of them does.
        let local = file_data_map(&same).await.unwrap();
        let (in_memory, _) =
            self_encryption::encrypt(bytes::Bytes::from(std::fs::read(&same).unwrap())).unwrap();
        assert!(local == in_memory);
        assert!(file_matches(&local, Some(&proven)).unwrap());
        // The map a proof reveals compares too.
        let revealed = proof_data_map(&record).unwrap();
        assert!(file_matches(&local, Some(&revealed)).unwrap());
        // Another file doesn't match.
        let other = file_data_map(&other).await.unwrap();
        assert!(!file_matches(&other, Some(&proven)).unwrap());
        // A proof that doesn't reveal the map can't be compared.
        let mut unrevealed = record;
        unrevealed.data_map = None;
        unrevealed.salt = None;
        assert!(proof_data_map(&unrevealed).is_err());
        assert!(file_matches(&local, None).is_err());
    }

    #[test]
    fn a_partly_sampled_estimate_shows_the_extra_chunk_as_a_floor() {
        use CostEstimateConfidence::{
            AllSamplesAlreadyStoredIncomplete, PricedSample, VerifiedAllAlreadyStored,
        };
        let price = "3000000000000000";
        let gas = "150000000000000";
        assert_eq!(
            cost_text(PricedSample, price, gas, "TEST"),
            format_cost(price, 150_000_000_000_000, "TEST")
        );
        assert_eq!(
            cost_text(VerifiedAllAlreadyStored, "0", "0", "TEST"),
            "already stored on the network — free"
        );
        assert_eq!(
            cost_text(AllSamplesAlreadyStoredIncomplete, "0", "0", "TEST"),
            "likely already stored — free (confirmed at payment)"
        );
        // Only the envelope (or data map) was quoted, and some content wasn't
        // sampled: its price, not a promise for the whole upload.
        let text = cost_text(AllSamplesAlreadyStoredIncomplete, price, gas, "TEST");
        assert!(
            text.starts_with(&format_cost(price, 150_000_000_000_000, "TEST")),
            "{text}"
        );
        assert!(text.contains("likely already stored"), "{text}");
    }

    #[test]
    fn costs_are_shown_in_the_given_token() {
        assert_eq!(
            format_cost("1250000000000000000", 0, "TEST"),
            "1.25 TEST (gas: free)"
        );
        assert_eq!(format_storage_cost("3000000000000000", "ANT"), "0.0030 ANT");
        assert_eq!(
            format_storage_cost("2500000000", "tokens"),
            "2.50 nanotokens"
        );
        assert_eq!(format_storage_cost("0", "TEST"), "free");
    }

    #[test]
    fn proofs_are_named_after_their_record() {
        assert_eq!(
            default_proof_path(Path::new("dir/notes.txt.record")),
            PathBuf::from("dir/notes.txt.proof")
        );
        assert_eq!(
            default_proof_path(Path::new("notes.txt-2.record")),
            PathBuf::from("notes.txt-2.proof")
        );
        assert_eq!(
            default_proof_path(Path::new("saved.hex")),
            PathBuf::from("saved.hex.proof")
        );
    }
}
