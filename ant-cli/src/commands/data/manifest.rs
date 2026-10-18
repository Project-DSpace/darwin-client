//! Manifest commands (ADR-0006).
//!
//! A manifest is a torrent-like description of a set of files. It is shared
//! off the network as a `.darwin` file or a `darwin://manifest/...` link,
//! never stored on the network. Upstream's `.ant` files and `ant://` links
//! are read too.
//!
//! Every readable upload the CLI performs is also recorded as a manifest in
//! the upload history, `darwin-uploads` under the data directory, so
//! `darwin manifest list` can show it and `darwin manifest download <ID>`
//! can fetch it again: a `darwin file upload` by the address it stored, a
//! `darwin manifest create` as the manifest written. A private upload is not
//! recorded: its data map stays only in its `.datamap` and `.record`, or in
//! the manifest file written.

use std::ffi::OsString;
use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ant_core::ant_listings::{is_envelope, Envelope, EnvelopeProof};
use ant_core::data::manifest::path::PATH_SEPARATOR;
use ant_core::data::{
    apply_compaction, compute_address, data_map_address, default_history_dir, embeddable_data_map,
    extract_manifest, forget_upload_record, format_timestamp, is_link, list_uploads, load_upload,
    manifest_filename_for, manifest_link_bytes, manifest_link_from_bytes, parse_link,
    plan_compaction, publish_data_maps, read_manifest_file, record_upload, write_manifest_file,
    BuildEvent, BuildOptions, BuildResult, Client, CollisionPolicy, CompactPlan, ContentRef,
    DataMap, DownloadEvent, EntryStatus, EnvelopeOptions, ExtractEvent, ExtractOptions, Link,
    Manifest, ManifestBuilder, ManifestError, PaymentMode, ReferenceMode, TorrentReference,
    UploadEvent, UploadRecord, UploadedEnvelope, MANIFEST_LINK_RECOMMENDED_MAX_BYTES,
};
use ant_core::datamap_file::write_upload_files;
use clap::Subcommand;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::file::{
    hidden_names, join_problems, payment_mode, record_note, upload_choices_json, EnvelopeChoices,
    UploadChoicesJson,
};
use crate::progress;

/// Entries downloaded at once unless `--concurrency` says otherwise.
const DEFAULT_CONCURRENCY: usize = 1;
/// Capacity of the progress channels between core and the terminal UI.
const PROGRESS_CHANNEL_CAPACITY: usize = 64;
/// Separator between address and path in `--public-file ADDRESS=PATH`.
const PUBLIC_FILE_SEPARATOR: char = '=';
/// Exit code for a second Ctrl-C, matching the shell convention for SIGINT.
const FORCE_QUIT_EXIT_CODE: i32 = 130;
/// Marks a size in `manifest show` that only the manifest's creator vouches for.
const CLAIMED_SIZE_MARK: char = '*';

/// Manifest subcommands.
#[derive(Subcommand, Debug)]
pub enum ManifestAction {
    /// Upload files and write a manifest describing them.
    ///
    /// One directory: its contents become the entries and its name the
    /// manifest name. Otherwise each path is added under its own name.
    ///
    /// Each file is uploaded as `darwin file upload` uploads it, with the
    /// same --visibility, --public, --readable, --index and --hide choices:
    /// private by default, in an envelope that shows every payment field.
    /// Each file's record is saved in `<manifest>.records/` next to the
    /// manifest.
    Create {
        /// Files or directories to upload.
        paths: Vec<PathBuf>,
        /// Where to write the manifest. Defaults to `<name>.darwin` here.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Manifest name, used as the default extraction directory. Not
        /// stored in any file's envelope.
        #[arg(long)]
        name: Option<String>,
        /// Reference files by public address where their DataMap chunk is
        /// already on the network, to keep the manifest small. Never
        /// publishes anything itself.
        #[arg(long)]
        compact: bool,
        /// Who can read the files, whether they are listed, and which
        /// payment fields are hidden, as for `darwin file upload`.
        #[command(flatten)]
        choices: EnvelopeChoices,
        /// Follow symlinks to regular files instead of skipping them.
        #[arg(long)]
        follow_symlinks: bool,
        /// Add an already-public file by address, optionally under PATH.
        #[arg(long = "public-file", value_name = "ADDRESS[=PATH]")]
        public_files: Vec<String>,
        /// Add an already-public file by address, fetching its DataMap and
        /// embedding it so recipients skip the DataMap fetch. A file stored
        /// with an envelope (as `darwin file upload --public` stores it) is
        /// added by its envelope address instead, which keeps its payment
        /// record; a private file's envelope is refused. Needs the network,
        /// no wallet.
        #[arg(long = "embed-public", value_name = "ADDRESS[=PATH]")]
        embed_public: Vec<String>,
        /// Record the BitTorrent info hash of the same files: 40 hex
        /// characters for v1, 64 for v2. Repeat to give both.
        #[arg(long = "torrent-hash", value_name = "HEX")]
        torrent_hashes: Vec<String>,
        /// Refused: batch (merkle) payments are off on the Darwin network.
        /// The vault lets a payer steer a batch's payout, and a re-sent batch
        /// can be charged twice, so every upload pays per chunk.
        #[arg(long, conflicts_with = "no_merkle")]
        merkle: bool,
        /// Per-chunk payments, always used; kept so scripts that pass it
        /// still run.
        #[arg(long, conflicts_with = "merkle", hide = true)]
        no_merkle: bool,
        /// Replace an existing manifest file at the output path.
        #[arg(long)]
        overwrite: bool,
        /// Also print the manifest as a `darwin://manifest/...` link.
        #[arg(long)]
        link: bool,
    },
    /// List every recorded upload, newest first.
    List,
    /// List the entries of a manifest.
    Show {
        /// A `.darwin` file, a `darwin://manifest/...` link, or an upload id
        /// from `darwin manifest list`.
        source: String,
    },
    /// Print a manifest as a `darwin://manifest/...` link. The link carries
    /// each embedded DataMap in its short published form.
    Link {
        /// A `.darwin` file, a `darwin://manifest/...` link, or an upload id
        /// from `darwin manifest list`.
        source: String,
    },
    /// Write a manifest out as a `.darwin` file, optionally compacted.
    ///
    /// `--compact` replaces embedded data maps with addresses for files
    /// already readable by address, including files uploaded with
    /// `darwin file upload --public`. A file not yet readable is listed with
    /// the standard way to make it so: `darwin file upload --visibility
    /// unlisted`, which stores it in an envelope. With `--yes`, the data maps
    /// of those files are published as plain chunks instead (paid), with no
    /// envelope: no payment record, listing or .record.
    Export {
        /// A `.darwin` file, a `darwin://manifest/...` link, or an upload id
        /// from `darwin manifest list`.
        source: String,
        /// Where to write the manifest. Defaults to `<name>.darwin` here.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Replace embedded data maps with the addresses their files are
        /// readable at. Needs the network; a wallet only with --yes.
        #[arg(long)]
        compact: bool,
        /// With --compact, publish the data maps of files not yet readable
        /// as plain chunks, with no envelope (paid; makes those files
        /// public).
        #[arg(long, short)]
        yes: bool,
        /// Replace an existing file at the output path.
        #[arg(long)]
        overwrite: bool,
        /// Also print the exported manifest as a `darwin://manifest/...` link.
        #[arg(long)]
        link: bool,
    },
    /// Download the files a manifest describes.
    Download {
        /// A `.darwin` file, a `darwin://manifest/...` link, or an upload id
        /// from `darwin manifest list`.
        source: String,
        /// Directory to extract into. Defaults to the manifest name, or
        /// the current directory when it has none.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Only extract these entries or directories. Repeatable.
        #[arg(long = "select", value_name = "PATH")]
        selection: Vec<String>,
        /// Replace existing regular files at target paths.
        #[arg(long)]
        overwrite: bool,
        /// Entries to download at once.
        #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
        concurrency: usize,
    },
}

impl ManifestAction {
    /// Check the upload choices of `create` (`--hide` and the visibility
    /// flags), so a mistake is named before the wallet key is asked for or
    /// the network is joined, as for `darwin file upload`.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Create { choices, .. } => create_upload_options(choices).map(|_| ()),
            _ => Ok(()),
        }
    }

    /// Whether the command talks to the network.
    pub fn needs_network(&self) -> bool {
        match self {
            Self::Create {
                paths,
                embed_public,
                ..
            } => !paths.is_empty() || !embed_public.is_empty(),
            Self::Download { .. } => true,
            Self::Export { compact, .. } => *compact,
            Self::List | Self::Show { .. } | Self::Link { .. } => false,
        }
    }

    /// Whether the command pays for anything.
    pub fn needs_wallet(&self) -> bool {
        match self {
            Self::Create { paths, .. } => !paths.is_empty(),
            // Compacting publishes, which is paid, only with --yes.
            Self::Export { compact, yes, .. } => *compact && *yes,
            Self::List | Self::Show { .. } | Self::Link { .. } | Self::Download { .. } => false,
        }
    }

    /// Run a command that needs no network.
    pub fn execute_offline(self, json: bool) -> anyhow::Result<()> {
        match self {
            Self::List => list_history(json),
            Self::Show { source } => show(&load_manifest(&source)?, json),
            Self::Link { source } => link(&load_manifest(&source)?, json),
            Self::Create {
                paths,
                output,
                name,
                public_files,
                embed_public,
                torrent_hashes,
                overwrite,
                link,
                ..
            } if paths.is_empty() && embed_public.is_empty() => {
                // Nothing to upload: a manifest over already-public files.
                let mut manifest = Manifest::new(name);
                manifest.torrent = parse_torrent_hashes(&torrent_hashes)?;
                for spec in &public_files {
                    let (address, path) = parse_public_file(spec)?;
                    manifest.entries.push(ant_core::data::ManifestEntry {
                        path,
                        size: None,
                        source: ContentRef::Public { address },
                    });
                }
                if manifest.entries.is_empty() {
                    anyhow::bail!("nothing to add: pass files, directories or --public-file");
                }
                manifest.canonicalize()?;
                let out = resolve_output(manifest.name.as_deref(), output)?;
                check_output_writable(&out, overwrite)?;
                write_manifest(&manifest, &out, overwrite)?;
                let history_id = record_upload_manifest(&manifest, None);
                report_created(&manifest, &out, None, history_id, link, json)
            }
            Self::Export {
                source,
                output,
                compact: false,
                overwrite,
                link,
                ..
            } => {
                let manifest = load_manifest(&source)?;
                let out = resolve_output(manifest.name.as_deref(), output)?;
                write_manifest(&manifest, &out, overwrite)?;
                report_exported(&manifest, &out, 0, link, json)
            }
            Self::Create { .. } | Self::Download { .. } | Self::Export { .. } => {
                anyhow::bail!("this command needs a network connection")
            }
        }
    }

    /// Run a command against the network.
    pub async fn execute(self, client: &Client, json: bool) -> anyhow::Result<()> {
        match self {
            Self::Create {
                paths,
                output,
                name,
                compact,
                choices,
                follow_symlinks,
                public_files,
                embed_public,
                torrent_hashes,
                merkle,
                no_merkle: _,
                overwrite,
                link,
            } => {
                let payment_mode = payment_mode(merkle)?;
                create(
                    client,
                    CreateArgs {
                        paths,
                        output,
                        name,
                        compact,
                        upload: create_upload_options(&choices)?,
                        follow_symlinks,
                        public_files,
                        embed_public,
                        torrent: parse_torrent_hashes(&torrent_hashes)?,
                        payment_mode,
                        overwrite,
                        link,
                    },
                    json,
                )
                .await
            }
            Self::Download {
                source,
                output,
                selection,
                overwrite,
                concurrency,
            } => {
                let concurrency = NonZeroUsize::new(concurrency)
                    .ok_or_else(|| anyhow::anyhow!("--concurrency must be at least 1"))?;
                download(
                    client,
                    &load_manifest(&source)?,
                    output,
                    selection,
                    overwrite,
                    concurrency,
                    json,
                )
                .await
            }
            Self::Export {
                source,
                output,
                compact: true,
                yes,
                overwrite,
                link,
            } => {
                let manifest = load_manifest(&source)?;
                export_compact(client, &manifest, output, yes, overwrite, link, json).await
            }
            Self::List | Self::Show { .. } | Self::Link { .. } | Self::Export { .. } => {
                self.execute_offline(json)
            }
        }
    }
}

/// `export --compact`: replace each embedded data map with the address its
/// file is readable at. A file readable by no address is named, with the
/// standard way to make it readable; with `--yes` its data map is published
/// as a plain chunk instead, with no envelope, after a warning that says so.
async fn export_compact(
    client: &Client,
    manifest: &Manifest,
    output: Option<PathBuf>,
    yes: bool,
    overwrite: bool,
    with_link: bool,
    json: bool,
) -> anyhow::Result<()> {
    // Nothing is published until the output is known to be writable.
    let out = resolve_output(manifest.name.as_deref(), output)?;
    check_output_writable(&out, overwrite)?;
    let cancel = CancellationToken::new();
    spawn_ctrl_c(cancel.clone());

    let plan = if json {
        plan_compaction(client, manifest, &cancel).await?
    } else {
        let spinner = progress::new_spinner("Checking which files are readable by address...");
        let plan = plan_compaction(client, manifest, &cancel).await;
        spinner.finish_and_clear();
        plan?
    };
    compaction_decision(&plan, yes)?;

    let published = plan.needs_publish.len();
    let plan = if plan.is_free() {
        plan
    } else {
        eprintln!("warning: {}", plain_publish_warning(&plan));
        info!("Publishing {published} data map chunk(s) with no envelope");
        if json {
            publish_data_maps(client, manifest, &plan.needs_publish, &cancel).await?;
        } else {
            let spinner =
                progress::new_spinner(&format!("Publishing {published} data map chunk(s)..."));
            let result = publish_data_maps(client, manifest, &plan.needs_publish, &cancel).await;
            spinner.finish_and_clear();
            result?;
        }
        plan.published()
    };

    let compacted = apply_compaction(manifest, &plan)?;
    write_manifest(&compacted, &out, overwrite)?;
    report_exported(&compacted, &out, published, with_link, json)
}

/// Whether a compaction plan can go ahead: when every embedded file is
/// readable by an address already, or with `--yes`, which publishes the
/// data maps of the others as plain chunks. Otherwise the files that aren't
/// readable are named, with the standard way to make each readable and the
/// `--yes` alternative.
fn compaction_decision(plan: &CompactPlan, yes: bool) -> anyhow::Result<()> {
    if plan.is_free() || yes {
        return Ok(());
    }
    anyhow::bail!(
        "{} file(s) have no public address yet:{}\n\
         Make each readable with `darwin file upload --visibility unlisted <FILE>` \
         (no --name, --content-type or --hide) and export again, or pass --yes to publish \
         their data maps as plain chunks: paid, and with no envelope, so no payment record, \
         listing or .record.",
        plan.needs_publish.len(),
        entry_names(plan)
    )
}

/// What `export --compact --yes` says before it publishes the data maps of
/// the files no address reads: they get no envelope.
fn plain_publish_warning(plan: &CompactPlan) -> String {
    format!(
        "publishing the data maps of {} file(s) as plain chunks, with no envelope: no payment \
         record, listing or .record (paid; makes those files public):{}",
        plan.needs_publish.len(),
        entry_names(plan)
    )
}

/// The names of the files a plan has to publish, one per line, indented.
fn entry_names(plan: &CompactPlan) -> String {
    plan.needs_publish
        .iter()
        .map(|entry| format!("\n  {}", entry.name))
        .collect()
}

fn report_exported(
    manifest: &Manifest,
    out: &Path,
    published: usize,
    with_link: bool,
    json: bool,
) -> anyhow::Result<()> {
    let link_text = if with_link {
        Some(make_link(manifest)?)
    } else {
        None
    };
    let embedded = manifest
        .entries
        .iter()
        .filter(|e| matches!(e.source, ContentRef::Embedded { .. }))
        .count();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "manifest_file": out.display().to_string(),
                "name": manifest.name,
                "torrent": torrent_json(manifest),
                "entries": entries_json(manifest)?,
                "embedded_entries": embedded,
                "public_entries": manifest.entries.len() - embedded,
                "data_maps_published": published,
                "link": link_text.as_ref().map(|(link, _)| link),
            }))?
        );
        return Ok(());
    }
    println!(
        "Wrote {} ({} embedded, {} public)",
        out.display(),
        embedded,
        manifest.entries.len() - embedded
    );
    if published > 0 {
        println!("Published {published} data map chunk(s), with no envelope");
    }
    if let Some((link, len)) = link_text {
        warn_if_long_link(len);
        println!("{link}");
    }
    Ok(())
}

struct CreateArgs {
    paths: Vec<PathBuf>,
    output: Option<PathBuf>,
    name: Option<String>,
    compact: bool,
    /// How each file is uploaded: the choices `darwin file upload` takes.
    upload: EnvelopeOptions,
    follow_symlinks: bool,
    public_files: Vec<String>,
    embed_public: Vec<String>,
    torrent: Option<TorrentReference>,
    payment_mode: PaymentMode,
    overwrite: bool,
    link: bool,
}

/// What `--embed-public` does with the record stored at a file's address.
#[derive(Debug)]
enum EmbedChoice {
    /// A plain data map: embed it, as upstream does.
    Embed(DataMap),
    /// A readable envelope, as `darwin file upload` stores one: the file is
    /// added by the envelope's address, the file's address, which keeps its
    /// payment record. Its data map is not embedded: an embedded entry is
    /// known by its plain data map's address, where nothing is stored, and
    /// compacting would then offer to store a second copy without an
    /// envelope.
    ByEnvelopeAddress,
    /// A private file's envelope: it withholds the data map.
    Withheld,
    /// Neither a data map nor a valid envelope, and why.
    Invalid(String),
}

/// How `--embed-public` adds the file whose record `bytes` was read from
/// `address`.
fn embed_choice(address: &[u8; 32], bytes: &[u8]) -> EmbedChoice {
    if compute_address(bytes) != *address {
        return EmbedChoice::Invalid("the record does not hash to its address".into());
    }
    if is_envelope(bytes) {
        return match Envelope::from_bytes(bytes) {
            Ok(envelope) if envelope.is_withheld() => EmbedChoice::Withheld,
            Ok(_) => EmbedChoice::ByEnvelopeAddress,
            Err(e) => EmbedChoice::Invalid(format!("not a valid envelope: {e}")),
        };
    }
    match rmp_serde::from_slice::<DataMap>(bytes) {
        Ok(map) => EmbedChoice::Embed(map),
        Err(e) => EmbedChoice::Invalid(format!("not a data map: {e}")),
    }
}

/// The upload options `create`'s flags ask for: those `darwin file upload`
/// takes, with no envelope metadata (`--name` names the manifest).
fn create_upload_options(choices: &EnvelopeChoices) -> anyhow::Result<EnvelopeOptions> {
    choices.options(None, None)
}

async fn create(client: &Client, args: CreateArgs, json: bool) -> anyhow::Result<()> {
    let single_dir = match args.paths.as_slice() {
        [only] if only.is_dir() => Some(only.clone()),
        _ => None,
    };
    let name = args.name.or_else(|| {
        single_dir
            .as_ref()
            .and_then(|d| d.file_name())
            .and_then(|n| n.to_str())
            .map(str::to_owned)
    });

    let options = BuildOptions {
        name,
        torrent: args.torrent,
        reference_mode: if args.compact {
            ReferenceMode::Compact
        } else {
            ReferenceMode::Embedded
        },
        // As `darwin file upload` uploads: in an envelope, unless the
        // choices need none (`--hide all`, not in the index).
        visibility: args.upload.clone().into_visibility(),
        payment_mode: args.payment_mode,
        follow_symlinks: args.follow_symlinks,
        cancel: CancellationToken::new(),
    };
    // Fail before any paid upload if the manifest could not be written.
    let out = resolve_output(options.name.as_deref(), args.output.clone())?;
    check_output_writable(&out, args.overwrite)?;
    spawn_ctrl_c(options.cancel.clone());
    let mut builder = ManifestBuilder::new(client, options);
    if let Some(dir) = &single_dir {
        builder.add_directory(dir, None)?;
    } else {
        for path in &args.paths {
            builder.add_path(path)?;
        }
    }
    for spec in &args.public_files {
        let (address, path) = parse_public_file(spec)?;
        builder.add_public(address, path, None)?;
    }
    for spec in &args.embed_public {
        let (address, path) = parse_public_file(spec)?;
        let hex_address = hex::encode(address);
        info!("Fetching public DataMap {hex_address}");
        // The record at the address, fetched once: a plain data map, or an
        // envelope as `darwin file upload` stores one.
        let record = client
            .chunk_get(&address)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch DataMap {hex_address}: {e}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("Failed to fetch DataMap {hex_address}: nothing is stored there")
            })?;
        match embed_choice(&address, &record.content) {
            EmbedChoice::Embed(data_map) => {
                // Embed the root map when it is small enough: recipients then
                // start on data chunks with no wrapper-record fetches.
                let data_map = embeddable_data_map(client, &data_map).await?;
                // An entry's identity is derived from its DataMap. A map
                // stored in some other form than an upload publishes would
                // derive a different address, so such a file is referenced by
                // its address instead.
                if data_map_address(&data_map)? == address {
                    builder.add_embedded(data_map, path, None)?;
                } else {
                    eprintln!(
                        "warning: the DataMap at {hex_address} is not in published form; \
                         adding it by address"
                    );
                    builder.add_public(address, path, None)?;
                }
            }
            EmbedChoice::ByEnvelopeAddress => {
                // Never the envelope's data map: an embedded entry is known
                // by its plain data map's address, where nothing is stored.
                eprintln!(
                    "note: {hex_address} is added by its envelope address, which keeps its \
                     payment record; its data map is not embedded"
                );
                builder.add_public(address, path, None)?;
            }
            EmbedChoice::Withheld => anyhow::bail!(
                "--embed-public {hex_address}: this address holds a private file's envelope: its \
                 data map is withheld (the envelope stores only a salted hash of it), so the file \
                 can be read only with the uploader's data map, and can't be added to a manifest \
                 by its address. Nothing was uploaded or paid."
            ),
            EmbedChoice::Invalid(why) => {
                anyhow::bail!("Failed to fetch DataMap {hex_address}: {why}")
            }
        }
    }
    if builder.pending_count() == 0 && args.public_files.is_empty() && args.embed_public.is_empty()
    {
        anyhow::bail!("nothing to add: the given paths contain no regular files");
    }

    // Said before anything is paid, as `darwin file upload` says it; the
    // choice stays the uploader's. Nothing to say when nothing is uploaded.
    let warnings: Vec<String> = if builder.pending_count() > 0 {
        args.upload
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect()
    } else {
        Vec::new()
    };
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    // A manifest of private uploads is not recorded in the upload history:
    // their data maps stay only in their records and the manifest file.
    let private = uploads_are_private(&args.upload, builder.pending_count() > 0);

    info!("Building manifest from {} file(s)", builder.pending_count());
    let start = Instant::now();
    let built = if json {
        builder.finish(None).await
    } else {
        let (tx, rx) = mpsc::channel(PROGRESS_CHANNEL_CAPACITY);
        let ui = tokio::spawn(drive_build_progress(rx));
        let result = builder.finish(Some(tx)).await;
        let _ = ui.await;
        result
    };

    let (result, history_id, records) = record_build_result(
        built,
        |manifest| history_record(private, manifest),
        |envelopes| save_records(&out, envelopes),
        &records_root_for(&out),
    )?;
    write_manifest(&result.manifest, &out, args.overwrite)?;
    if !json {
        eprintln!(
            "Uploaded {} file(s), {} new chunk(s) in {:.1}s",
            result.files_uploaded,
            result.chunks_stored,
            start.elapsed().as_secs_f64()
        );
        for skipped in &result.skipped_symlinks {
            eprintln!("Skipped symlink: {}", skipped.display());
        }
    }
    report_created(
        &result.manifest,
        &out,
        Some(&UploadReport {
            result: &result,
            options: &args.upload,
            records: &records,
            warnings,
            private,
        }),
        history_id,
        args.link,
        json,
    )
}

/// Persist completed uploads before reporting cancellation or failure: first
/// each uploaded file's envelope record (`save`), then the manifest in the
/// upload history (`record`). `records_root` is where `save` puts records.
fn record_build_result(
    built: Result<BuildResult, ManifestError>,
    record: impl FnOnce(&Manifest) -> Option<String>,
    save: impl FnOnce(&[UploadedEnvelope]) -> Vec<SavedRecord>,
    records_root: &Path,
) -> anyhow::Result<(BuildResult, Option<String>, Vec<SavedRecord>)> {
    let result = match built {
        Ok(result) => result,
        Err(ManifestError::BuildFailed {
            path,
            cause,
            partial,
        }) => {
            let records = save(&partial.envelopes);
            let history_id = record(&partial.manifest);
            anyhow::bail!(
                "manifest build failed at {path:?} after {} of {} file(s): {cause}{}{}",
                partial.files_uploaded,
                partial.total_to_upload,
                saved_records_message(&records, records_root),
                partial_record_message(history_id.as_deref()),
            );
        }
        Err(error) => return Err(error.into()),
    };

    let records = save(&result.envelopes);
    let history_id = record(&result.manifest);
    if result.cancelled {
        return Err(cancelled_build_error(
            &result,
            &saved_records_message(&records, records_root),
            history_id.as_deref(),
        ));
    }
    Ok((result, history_id, records))
}

/// Extension of the folder next to a manifest that holds its files' records.
const RECORDS_EXTENSION: &str = "records";

/// The folder next to the manifest file `out` that holds the records of the
/// files it uploaded: `out` with the extension `.records`, so `photos.records`
/// for `photos.darwin`. It is never `out` itself. It sits beside the
/// manifest, by default outside the uploaded directory, so a later upload of
/// that directory doesn't take in the records, which a private file's data
/// map and salt are in.
fn records_root_for(out: &Path) -> PathBuf {
    let root = out.with_extension(RECORDS_EXTENSION);
    if root != out {
        return root;
    }
    // `out` already ends in `.records`: add another.
    let mut name = out.file_name().map(OsString::from).unwrap_or_default();
    name.push(".");
    name.push(RECORDS_EXTENSION);
    out.with_file_name(name)
}

/// The folder for the record of the file at `entry_path` in the manifest
/// `out`: the manifest's records folder plus the entry's parent directories.
/// Entry paths are portable relative paths, checked before anything was
/// uploaded.
fn record_dir_for(out: &Path, entry_path: &str) -> PathBuf {
    let mut dir = records_root_for(out);
    if let Some((parent, _)) = entry_path.rsplit_once(PATH_SEPARATOR) {
        dir.extend(parent.split(PATH_SEPARATOR));
    }
    dir
}

/// Write `proof`, the record of the file at `entry_path`, in the records
/// folder of the manifest `out`, as `<file name>.record`. An existing record
/// is never replaced, whatever `--overwrite` says (it is about the manifest
/// file): the new one gets the first free `-N` suffix, since an old record
/// holds a salt nothing else keeps.
fn write_entry_record(
    out: &Path,
    entry_path: &str,
    proof: &EnvelopeProof,
) -> anyhow::Result<PathBuf> {
    let dir = record_dir_for(out, entry_path);
    let name = entry_path
        .rsplit(PATH_SEPARATOR)
        .next()
        .unwrap_or(entry_path);
    write_upload_files(
        &dir,
        name,
        None,
        Some(proof),
        CollisionPolicy::NumericSuffix,
    )?
    .record
    .ok_or_else(|| anyhow::anyhow!("no record was written for {entry_path}"))
}

/// What became of the envelope record of one uploaded file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SavedRecord {
    /// Manifest path of the file.
    path: String,
    /// The envelope's address: the file's address when it is readable.
    address: [u8; 32],
    /// Where the record was saved, if it was.
    record: Option<PathBuf>,
    /// Whether the record was checked against the chain.
    checked: bool,
    /// Why there is no record, why it wasn't saved, or why it wasn't
    /// checked.
    problem: Option<String>,
}

/// Save every uploaded file's envelope record in the manifest's records
/// folder, as `darwin file upload` saves a file's next to it, and say what
/// went wrong. A record kept under the client's data directory is removed
/// only once its copy is saved.
fn save_records(out: &Path, envelopes: &[UploadedEnvelope]) -> Vec<SavedRecord> {
    envelopes
        .iter()
        .map(|uploaded| save_record(out, uploaded))
        .collect()
}

fn save_record(out: &Path, uploaded: &UploadedEnvelope) -> SavedRecord {
    let envelope = &uploaded.envelope;
    let address = envelope.address();
    let mut saved = None;
    let mut save_problem = None;
    if let Some(proof) = &envelope.proof {
        match write_entry_record(out, &uploaded.path, proof) {
            Ok(path) => {
                // The record is saved: the copy the upload kept can go.
                if let Err(e) = forget_upload_record(&address) {
                    info!("Could not remove the upload's kept record: {e}");
                }
                saved = Some(path);
            }
            Err(e) => {
                if let Ok(text) = proof.to_hex() {
                    eprintln!(
                        "The record of {}, which could not be saved (a copy stays under the \
                         client's data directory, in payments/upload/records/):\n{text}",
                        uploaded.path
                    );
                }
                save_problem = Some(format!("the record could not be saved: {e}"));
            }
        }
    }
    let problem = join_problems(
        save_problem,
        record_note(
            envelope.proof.is_some(),
            envelope.proof_checked,
            envelope.proof_problem.as_deref(),
            saved.is_some(),
        ),
    );
    if let Some(note) = &problem {
        eprintln!("warning: {}: {note}", uploaded.path);
    }
    if envelope.proof.is_none() {
        // Without a record, the salt would be lost: say it once.
        if let Some(salt) = envelope.salt {
            eprintln!(
                "The private envelope's salt of {} (keep it with the manifest to prove the \
                 file): {}",
                uploaded.path,
                hex::encode(salt)
            );
        }
    }
    SavedRecord {
        path: uploaded.path.clone(),
        address,
        record: saved,
        checked: envelope.proof_checked,
        problem,
    }
}

/// Where the records of a failed or cancelled build were saved, if any were.
fn saved_records_message(records: &[SavedRecord], records_root: &Path) -> String {
    if records.iter().any(|record| record.record.is_some()) {
        format!(
            "; the records of the files uploaded are in {}",
            records_root.display()
        )
    } else {
        String::new()
    }
}

/// What a manifest of private uploads says in place of its upload history id.
const NOT_RECORDED_PRIVATE_MANIFEST: &str = "Not recorded in the upload history: a private \
     upload's data map stays only in its .record and in the manifest file written.";

/// Whether a build that uploads files (`uploading`) with `options` makes a
/// manifest of private uploads, whose data maps it embeds.
fn uploads_are_private(options: &EnvelopeOptions, uploading: bool) -> bool {
    uploading && !options.readable
}

/// Record a built manifest in the upload history, unless it holds private
/// uploads (`private`): their data maps are kept only in their records and
/// the manifest file the user chose, never under the client's data
/// directory.
fn history_record(private: bool, manifest: &Manifest) -> Option<String> {
    if private {
        None
    } else {
        record_upload_manifest(manifest, None)
    }
}

/// What `create` reports about the files it uploaded.
struct UploadReport<'a> {
    result: &'a BuildResult,
    /// How the files were uploaded.
    options: &'a EnvelopeOptions,
    /// Each envelope's record.
    records: &'a [SavedRecord],
    /// What the choices give away, as said before uploading.
    warnings: Vec<String>,
    /// Whether the files were uploaded private, so the manifest was not
    /// recorded in the upload history.
    private: bool,
}

/// One uploaded file's envelope and record in `create`'s JSON: its path and
/// the fields `darwin file upload`'s JSON has for them.
#[derive(serde::Serialize)]
struct EnvelopeJson<'a> {
    path: &'a str,
    #[serde(flatten)]
    choices: UploadChoicesJson,
}

fn envelope_json<'a>(options: &EnvelopeOptions, record: &'a SavedRecord) -> EnvelopeJson<'a> {
    EnvelopeJson {
        path: &record.path,
        choices: upload_choices_json(
            options,
            Some((hex::encode(record.address), record.checked)),
            record.record.as_deref(),
            record.problem.clone(),
            Vec::new(),
        ),
    }
}

/// The output path: the one given, or `<name>.darwin` in the current
/// directory.
fn resolve_output(name: Option<&str>, output: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(name) = name {
        ant_core::data::manifest::path::validate_component(name)
            .map_err(ManifestError::InvalidName)?;
    }
    Ok(output.unwrap_or_else(|| PathBuf::from(manifest_filename_for(name))))
}

fn resolve_download_root(manifest: &Manifest, output: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    manifest.validate()?;
    Ok(output.unwrap_or_else(|| {
        manifest
            .name
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }))
}

fn partial_record_message(history_id: Option<&str>) -> String {
    history_id
        .map(|id| format!("; the partial manifest is recorded as {id}"))
        .unwrap_or_default()
}

/// `records`: where the uploaded files' records were saved
/// ([`saved_records_message`]).
fn cancelled_build_error(
    result: &ant_core::data::BuildResult,
    records: &str,
    history_id: Option<&str>,
) -> anyhow::Error {
    anyhow::anyhow!(
        "cancelled after {} of {} file(s){records}{}",
        result.files_uploaded,
        result.total_to_upload,
        partial_record_message(history_id),
    )
}

/// Refuse up front when the output exists and may not be replaced, so no
/// paid work happens for a manifest that could not be written.
fn check_output_writable(out: &Path, overwrite: bool) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(out) {
        Ok(meta) if meta.is_dir() => anyhow::bail!("{} is a directory", out.display()),
        Ok(_) if !overwrite => anyhow::bail!(
            "{} already exists; pass --overwrite to replace it",
            out.display()
        ),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("cannot check {}: {e}", out.display())),
    }
}

fn write_manifest(manifest: &Manifest, out: &Path, overwrite: bool) -> anyhow::Result<()> {
    write_manifest_file(out, manifest, overwrite)
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", out.display()))
}

/// Turn the first Ctrl-C into a cancellation and a second one into an exit.
fn spawn_ctrl_c(cancel: CancellationToken) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("Cancelling... press Ctrl-C again to quit immediately");
            cancel.cancel();
        }
        if tokio::signal::ctrl_c().await.is_ok() {
            std::process::exit(FORCE_QUIT_EXIT_CODE);
        }
    });
}

/// Record an upload in the history, warning instead of failing when the
/// history directory is unusable: the upload itself has already succeeded.
pub fn record_upload_manifest(manifest: &Manifest, label: Option<&str>) -> Option<String> {
    let recorded = default_history_dir().and_then(|dir| record_upload(&dir, manifest, label));
    match recorded {
        Ok(record) => Some(record.id),
        Err(e) => {
            eprintln!(
                "warning: upload succeeded but could not be recorded in the upload history: {e}"
            );
            None
        }
    }
}

fn report_created(
    manifest: &Manifest,
    out: &Path,
    uploads: Option<&UploadReport<'_>>,
    history_id: Option<String>,
    with_link: bool,
    json: bool,
) -> anyhow::Result<()> {
    let link_text = if with_link {
        Some(make_link(manifest)?)
    } else {
        None
    };
    if json {
        let mut value = json!({
            "manifest_file": out.display().to_string(),
            "name": manifest.name,
                "torrent": torrent_json(manifest),
            "entries": entries_json(manifest)?,
            "total_size": manifest.total_size(),
            "link": link_text.as_ref().map(|(link, _)| link),
            "history_id": history_id,
        });
        if let Some(uploads) = uploads {
            let r = uploads.result;
            value["files_uploaded"] = json!(r.files_uploaded);
            value["chunks_stored"] = json!(r.chunks_stored);
            value["storage_cost_atto"] = json!(r.storage_cost_atto.to_string());
            value["gas_cost_wei"] = json!(r.gas_cost_wei.to_string());
            value["skipped_symlinks"] = json!(r
                .skipped_symlinks
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>());
            value["envelopes"] = serde_json::to_value(
                uploads
                    .records
                    .iter()
                    .map(|record| envelope_json(uploads.options, record))
                    .collect::<Vec<_>>(),
            )?;
            if !uploads.warnings.is_empty() {
                value["warnings"] = json!(uploads.warnings);
            }
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!(
        "Wrote {} ({} entr{})",
        out.display(),
        manifest.entries.len(),
        if manifest.entries.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    if let Some(uploads) = uploads.filter(|uploads| !uploads.records.is_empty()) {
        let hidden = hidden_names(uploads.options);
        if hidden.is_empty() {
            println!("Payment: all fields shown");
        } else {
            println!("Payment: hidden: {}", hidden.join(", "));
        }
        println!("Envelopes:");
        for record in uploads.records {
            let address = hex::encode(record.address);
            match &record.record {
                Some(saved) => println!(
                    "  {}: envelope {address}, record {}",
                    record.path,
                    saved.display()
                ),
                None => println!("  {}: envelope {address}, no record", record.path),
            }
        }
        if !uploads.options.readable && uploads.records.iter().any(|r| r.record.is_some()) {
            println!(
                "Keep the records as safe as the manifest: a private file's record holds its \
                 data map and salt, so it reads the file. `darwin file prove --no-reveal` \
                 proves only the payment."
            );
        }
    }
    if let Some(id) = history_id {
        println!("Recorded as {id} (darwin manifest download {id})");
    } else if uploads.is_some_and(|uploads| uploads.private) {
        println!("{NOT_RECORDED_PRIVATE_MANIFEST}");
    }
    if let Some((link, len)) = link_text {
        warn_if_long_link(len);
        println!("{link}");
    }
    Ok(())
}

fn list_history(json: bool) -> anyhow::Result<()> {
    let dir = default_history_dir()?;
    let listing = list_uploads(&dir)?;
    if json {
        let records: Vec<_> = listing
            .records
            .iter()
            .map(|r| {
                json!({
                    "id": r.id,
                    "recorded_at": r.recorded_at,
                    "recorded_at_utc": format_timestamp(r.recorded_at),
                    "name": r.manifest.name,
                    "entries": r.manifest.entries.len(),
                    "total_size": r.manifest.total_size(),
                    "file": r.path.display().to_string(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "history_dir": dir.display().to_string(),
                "records": records,
                "unreadable": listing
                    .unreadable
                    .iter()
                    .map(|(p, e)| json!({"file": p.display().to_string(), "error": e}))
                    .collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }
    if listing.records.is_empty() {
        println!("No recorded uploads in {}", dir.display());
    } else {
        println!(
            "{:<23}  {:>7}  {:>12}  ID",
            "RECORDED (UTC)", "ENTRIES", "SIZE"
        );
        for r in &listing.records {
            print_history_row(r);
        }
    }
    for (path, error) in &listing.unreadable {
        eprintln!("warning: unreadable record {}: {error}", path.display());
    }
    Ok(())
}

fn print_history_row(record: &UploadRecord) {
    let size = record
        .manifest
        .total_size()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "?".to_string());
    // Drop the trailing " UTC"; the header already says so.
    let stamp = format_timestamp(record.recorded_at);
    let stamp = stamp.strip_suffix(" UTC").unwrap_or(&stamp);
    println!(
        "{:<23}  {:>7}  {:>12}  {}",
        stamp,
        record.manifest.entries.len(),
        size,
        record.id
    );
}

fn show(manifest: &Manifest, json: bool) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "name": manifest.name,
                "torrent": torrent_json(manifest),
                "total_size": manifest.total_size(),
                "entries": entries_json(manifest)?,
            }))?
        );
        return Ok(());
    }
    println!("Name:    {}", manifest.name.as_deref().unwrap_or("(none)"));
    if let Some(torrent) = &manifest.torrent {
        if let Some(v1) = torrent.info_hash_v1 {
            println!("Torrent: v1 {}", hex::encode(v1));
        }
        if let Some(v2) = torrent.info_hash_v2 {
            println!("Torrent: v2 {}", hex::encode(v2));
        }
    }
    println!("Entries: {}", manifest.entries.len());
    if let Some(total) = manifest.total_size() {
        println!("Size:    {total} bytes");
    }
    println!();
    let mut any_claimed = false;
    for entry in &manifest.entries {
        // A size read from an embedded root DataMap is exact; the recorded
        // `size` is only the creator's claim and is marked as such.
        let size = match (entry.known_size(), entry.size) {
            (Some(known), _) => known.to_string(),
            (None, Some(claimed)) => {
                any_claimed = true;
                format!("{claimed}{CLAIMED_SIZE_MARK}")
            }
            (None, None) => "?".to_string(),
        };
        println!(
            "{:>12}  {:<9} {}",
            size,
            entry.source.kind(),
            entry.effective_name()?
        );
    }
    if any_claimed {
        println!();
        println!("{CLAIMED_SIZE_MARK} size as recorded by the manifest's creator, not verified");
    }
    Ok(())
}

fn link(manifest: &Manifest, json: bool) -> anyhow::Result<()> {
    let (link, len) = make_link(manifest)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "link": link,
                "manifest_bytes": len,
                "recommended_max_bytes": MANIFEST_LINK_RECOMMENDED_MAX_BYTES,
            }))?
        );
        return Ok(());
    }
    warn_if_long_link(len);
    println!("{link}");
    Ok(())
}

/// A manifest link and the length of the manifest bytes it carries, encoded
/// once.
fn make_link(manifest: &Manifest) -> anyhow::Result<(String, usize)> {
    let bytes = manifest_link_bytes(manifest)?;
    Ok((manifest_link_from_bytes(&bytes), bytes.len()))
}

fn warn_if_long_link(len: usize) {
    if len > MANIFEST_LINK_RECOMMENDED_MAX_BYTES {
        eprintln!(
            "warning: this manifest is {len} bytes; links above \
             {MANIFEST_LINK_RECOMMENDED_MAX_BYTES} bytes are long for a chat message. \
             Consider sharing the .darwin file instead."
        );
    }
}

async fn download(
    client: &Client,
    manifest: &Manifest,
    output: Option<PathBuf>,
    selection: Vec<String>,
    overwrite: bool,
    concurrency: NonZeroUsize,
    json: bool,
) -> anyhow::Result<()> {
    let output_root = resolve_download_root(manifest, output)?;
    let options = ExtractOptions {
        output_root: output_root.clone(),
        selection,
        overwrite,
        concurrency,
        cancel: CancellationToken::new(),
    };
    spawn_ctrl_c(options.cancel.clone());
    info!("Extracting manifest into {}", output_root.display());
    let start = Instant::now();

    let report = if json {
        extract_manifest(client, manifest, &options, None).await?
    } else {
        let (tx, rx) = mpsc::channel(PROGRESS_CHANNEL_CAPACITY);
        let ui = tokio::spawn(drive_extract_progress(rx));
        let report = extract_manifest(client, manifest, &options, Some(tx)).await;
        let _ = ui.await;
        report?
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "output": output_root.display().to_string(),
                "written": report.written(),
                "failed": report.failed(),
                "cancelled": report.cancelled(),
                "entries": report.entries,
            }))?
        );
    } else {
        for e in &report.entries {
            match &e.status {
                EntryStatus::Written { bytes } => println!("written   {} ({bytes} bytes)", e.name),
                EntryStatus::Failed { error } => println!("failed    {}: {error}", e.name),
                EntryStatus::Cancelled => println!("cancelled {}", e.name),
            }
        }
        eprintln!(
            "{} written, {} failed in {:.1}s -> {}",
            report.written(),
            report.failed(),
            start.elapsed().as_secs_f64(),
            output_root.display()
        );
    }
    if report.cancelled() > 0 {
        anyhow::bail!(
            "cancelled with {} entr(y/ies) not downloaded",
            report.cancelled()
        );
    }
    if report.failed() > 0 {
        anyhow::bail!("{} entr(y/ies) failed to download", report.failed());
    }
    Ok(())
}

/// Load a manifest from a `darwin://manifest/...` link (or upstream's
/// `ant://manifest/...`), a manifest file (read by its content, so `.darwin`
/// and `.ant` files both open), or an upload id from the history, tried in
/// that order.
fn load_manifest(source: &str) -> anyhow::Result<Manifest> {
    if is_link(source) {
        return match parse_link(source)? {
            Link::Manifest(m) => Ok(m),
            Link::File(_) => anyhow::bail!(
                "this is a file link, not a manifest link; use `darwin file download` for it"
            ),
        };
    }
    let path = Path::new(source);
    if path.is_file() {
        return read_manifest_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to read manifest {source}: {e}"));
    }
    let dir = default_history_dir()?;
    match load_upload(&dir, source)? {
        Some(record) => Ok(record.manifest),
        None => anyhow::bail!(
            "{source} is not a manifest file, a manifest link, or a recorded upload id \
             (see `darwin manifest list`)"
        ),
    }
}

/// Parse the `--torrent-hash` values into one reference, or `None` if none.
fn parse_torrent_hashes(hashes: &[String]) -> anyhow::Result<Option<TorrentReference>> {
    let mut merged: Option<TorrentReference> = None;
    for hash in hashes {
        let parsed = TorrentReference::parse_hex(hash)?;
        merged = Some(match merged {
            Some(existing) => existing.merge(parsed)?,
            None => parsed,
        });
    }
    Ok(merged)
}

/// Hex form of a torrent reference for JSON output.
fn torrent_json(manifest: &Manifest) -> serde_json::Value {
    match &manifest.torrent {
        Some(t) => json!({
            "info_hash_v1": t.info_hash_v1.map(hex::encode),
            "info_hash_v2": t.info_hash_v2.map(hex::encode),
        }),
        None => serde_json::Value::Null,
    }
}

/// Parse `ADDRESS[=PATH]` for `--public-file`.
fn parse_public_file(spec: &str) -> anyhow::Result<([u8; 32], Option<String>)> {
    let (address_text, path) = match spec.split_once(PUBLIC_FILE_SEPARATOR) {
        Some((a, p)) => (a, Some(p.to_string())),
        None => (spec, None),
    };
    match parse_link(address_text)? {
        Link::File(address) => Ok((address, path)),
        Link::Manifest(_) => anyhow::bail!("--public-file takes a file address, not a manifest"),
    }
}

fn entries_json(manifest: &Manifest) -> anyhow::Result<Vec<serde_json::Value>> {
    manifest
        .entries
        .iter()
        .map(|entry| {
            Ok(json!({
                "name": entry.effective_name()?,
                "path": entry.path,
                "size": entry.size,
                "known_size": entry.known_size(),
                "kind": entry.source.kind(),
                "address": hex::encode(entry.source.content_address()?),
            }))
        })
        .collect()
}

async fn drive_build_progress(mut rx: mpsc::Receiver<BuildEvent>) {
    let spinner = progress::new_spinner("Preparing upload...");
    let mut current = String::new();
    let mut position = String::new();
    while let Some(event) = rx.recv().await {
        match event {
            BuildEvent::FileStarted { path, index, total } => {
                current = path;
                position = format!("[{}/{total}]", index + 1);
                spinner.set_message(format!("{position} {current}: encrypting"));
            }
            BuildEvent::Upload { event, .. } => {
                let phase = match event {
                    UploadEvent::Encrypting { chunks_done } => {
                        format!("encrypting ({chunks_done})")
                    }
                    UploadEvent::Encrypted { total_chunks } => {
                        format!("encrypted {total_chunks} chunks")
                    }
                    UploadEvent::QuotingChunks {
                        wave, total_waves, ..
                    } => {
                        format!("quoting wave {wave}/{total_waves}")
                    }
                    UploadEvent::ChunkQuoted { quoted, total } => {
                        format!("quoted {quoted}/{total}")
                    }
                    UploadEvent::ChunkStored { stored, total } => {
                        format!("stored {stored}/{total}")
                    }
                };
                spinner.set_message(format!("{position} {current}: {phase}"));
            }
            BuildEvent::FileFinished {
                path,
                chunks_stored,
                reference,
            } => {
                spinner.println(format!(
                    "uploaded {path} ({chunks_stored} new chunks, {reference})"
                ));
            }
        }
    }
    spinner.finish_and_clear();
}

async fn drive_extract_progress(mut rx: mpsc::Receiver<ExtractEvent>) {
    let spinner = progress::new_spinner("Preparing download...");
    while let Some(event) = rx.recv().await {
        match event {
            ExtractEvent::EntryStarted { name, index, total } => {
                spinner.set_message(format!("[{}/{total}] {name}: resolving", index + 1));
            }
            ExtractEvent::Download { name, event } => {
                let phase = match event {
                    DownloadEvent::ResolvingDataMap { total_map_chunks } => {
                        format!("resolving data map ({total_map_chunks} chunks)")
                    }
                    DownloadEvent::MapChunkFetched { fetched } => {
                        format!("resolving data map ({fetched} fetched)")
                    }
                    DownloadEvent::DataMapResolved { total_chunks } => {
                        format!("fetching {total_chunks} chunks")
                    }
                    DownloadEvent::ChunksFetched { fetched, total } => {
                        format!("fetched {fetched}/{total}")
                    }
                };
                spinner.set_message(format!("{name}: {phase}"));
            }
            ExtractEvent::EntryFinished { .. } => {}
        }
    }
    spinner.finish_and_clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_names_are_rejected_before_export_or_download_root_selection() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        for name in [
            "../outside",
            "/tmp/outside",
            "a/b",
            outside.to_str().unwrap(),
        ] {
            let manifest = Manifest {
                name: Some(name.into()),
                torrent: None,
                entries: vec![ant_core::data::ManifestEntry {
                    path: Some("valid.bin".into()),
                    size: None,
                    source: ContentRef::Public { address: [1; 32] },
                }],
            };
            let mut bytes = ant_core::data::manifest::MANIFEST_MAGIC.to_vec();
            bytes.push(ant_core::data::manifest::MANIFEST_FORMAT_VERSION);
            bytes.extend(rmp_serde::to_vec_named(&manifest).unwrap());
            let source = dir.path().join("incoming.ant");
            std::fs::write(&source, bytes).unwrap();
            let action = ManifestAction::Export {
                source: source.to_string_lossy().into_owned(),
                // Keep any regression's writes inside the fixture; the
                // contained absolute-name case exercises default export.
                output: if name == outside.to_str().unwrap() {
                    None
                } else {
                    Some(dir.path().join("export.ant"))
                },
                compact: false,
                yes: false,
                overwrite: false,
                link: false,
            };
            assert!(action.execute_offline(false).is_err());
            assert!(resolve_output(Some(name), None).is_err());
            assert!(resolve_download_root(&manifest, None).is_err());
        }
        assert!(!outside.with_extension("darwin").exists());
        assert!(!outside.with_extension("ant").exists());

        let valid = Manifest::new(Some("pack".into()));
        assert_eq!(
            resolve_output(Some("pack"), None).unwrap(),
            PathBuf::from("pack.darwin")
        );
        assert_eq!(
            resolve_output(None, None).unwrap(),
            PathBuf::from("manifest.darwin")
        );
        assert_eq!(
            resolve_download_root(&valid, None).unwrap(),
            PathBuf::from("pack")
        );
        let explicit = dir.path().join("chosen/destination");
        assert_eq!(
            resolve_output(Some("pack"), Some(explicit.clone())).unwrap(),
            explicit
        );
        assert_eq!(
            resolve_download_root(&valid, Some(explicit.clone())).unwrap(),
            explicit
        );
        assert_eq!(
            resolve_download_root(&Manifest::new(None), None).unwrap(),
            PathBuf::from(".")
        );
    }

    #[test]
    fn cancellation_reports_original_upload_total_regardless_of_reference_entries() {
        let mut result = ant_core::data::BuildResult {
            manifest: Manifest::new(None),
            cancelled: true,
            skipped_symlinks: vec![],
            files_uploaded: 1,
            total_to_upload: 10,
            chunks_stored: 3,
            storage_cost_atto: 0,
            gas_cost_wei: 0,
            envelopes: vec![],
        };
        for index in 0..3 {
            result.manifest.entries.push(ant_core::data::ManifestEntry {
                path: Some(format!("file-{index}")),
                size: None,
                source: ContentRef::Public {
                    address: [index; 32],
                },
            });
            assert_eq!(
                cancelled_build_error(&result, "", Some("record-id")).to_string(),
                "cancelled after 1 of 10 file(s); the partial manifest is recorded as record-id"
            );
        }
        assert_eq!(
            cancelled_build_error(&result, "; the records are in x.records", None).to_string(),
            "cancelled after 1 of 10 file(s); the records are in x.records"
        );
    }

    #[test]
    fn build_failure_and_cancellation_are_recorded_before_returning_an_error() {
        let manifest = Manifest {
            name: Some("partial".into()),
            torrent: None,
            entries: vec![ant_core::data::ManifestEntry {
                path: Some("completed.bin".into()),
                size: Some(10),
                source: ContentRef::Public { address: [1; 32] },
            }],
        };
        for cancelled in [false, true] {
            let partial = BuildResult {
                manifest: manifest.clone(),
                cancelled,
                skipped_symlinks: vec![],
                files_uploaded: 1,
                total_to_upload: 2,
                chunks_stored: 3,
                storage_cost_atto: 12,
                gas_cost_wei: 34,
                envelopes: vec![],
            };
            let built = if cancelled {
                Ok(partial)
            } else {
                Err(ManifestError::BuildFailed {
                    path: "later.bin".into(),
                    cause: Box::new(ManifestError::Build("forced failure".into())),
                    partial: Box::new(partial),
                })
            };
            let history = tempfile::tempdir().unwrap();
            // The paid files' records are saved first, then the manifest is
            // recorded, before the error is returned.
            let saved = std::cell::Cell::new(0);
            let error = record_build_result(
                built,
                |manifest| {
                    assert_eq!(saved.get(), 1, "records are saved first");
                    Some(record_upload(history.path(), manifest, None).unwrap().id)
                },
                |envelopes| {
                    saved.set(saved.get() + 1);
                    assert!(envelopes.is_empty());
                    vec![SavedRecord {
                        path: "completed.bin".into(),
                        address: [7; 32],
                        record: Some(PathBuf::from("partial.records/completed.bin.record")),
                        checked: true,
                        problem: None,
                    }]
                },
                Path::new("partial.records"),
            )
            .unwrap_err();
            assert_eq!(saved.get(), 1);
            let listing = list_uploads(history.path()).unwrap();
            assert_eq!(listing.records.len(), 1);
            assert_eq!(listing.records[0].manifest, manifest);
            let error = error.to_string();
            assert!(error.contains(&listing.records[0].id), "{error}");
            assert!(error.contains("1 of 2 file(s)"), "{error}");
            assert!(
                error.contains("the records of the files uploaded are in partial.records"),
                "{error}"
            );
            if !cancelled {
                assert!(error.contains("later.bin"));
                assert!(error.contains("forced failure"));
            }
        }
    }

    /// A manifest's records go in a folder beside it, named after it, under
    /// each entry's parent directories: never inside the uploaded tree, and
    /// never the manifest file itself.
    #[test]
    fn records_go_in_a_folder_beside_the_manifest() {
        // `darwin manifest create photos`: entries are relative to photos/,
        // the manifest is photos.darwin beside it.
        let out = Path::new("photos.darwin");
        assert_eq!(records_root_for(out), PathBuf::from("photos.records"));
        assert_eq!(
            record_dir_for(out, "a.jpg"),
            PathBuf::from("photos.records")
        );
        assert_eq!(
            record_dir_for(out, "2026/summer/a.jpg"),
            ["photos.records", "2026", "summer"]
                .iter()
                .collect::<PathBuf>()
        );
        assert!(!record_dir_for(out, "2026/a.jpg").starts_with("photos"));
        let out = Path::new("shared").join("album.darwin");
        assert_eq!(
            record_dir_for(&out, "b.bin"),
            Path::new("shared").join("album.records")
        );
        assert_eq!(record_dir_for(&out, "b.bin").parent(), out.parent());
        // An output without an extension, or already named `.records`.
        assert_eq!(
            records_root_for(Path::new("album")),
            PathBuf::from("album.records")
        );
        assert_eq!(
            records_root_for(Path::new("album.records")),
            PathBuf::from("album.records.records")
        );
    }

    /// A record is never written over another: an existing `x.record`, which
    /// holds a salt nothing else keeps, makes the new one `x-2.record`.
    #[test]
    fn a_record_never_replaces_an_existing_one() {
        use ant_core::ant_listings::{
            encode_data_map, self_encryption, Envelope, Metadata, ShownFields,
        };
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("album.darwin");
        let (map, _) = self_encryption::encrypt(bytes::Bytes::from(vec![5u8; 4_000])).unwrap();
        let salt = [9; 32];
        let envelope =
            Envelope::withheld(&map, &salt, Metadata::default(), ShownFields::ALL, false).unwrap();
        let record = EnvelopeProof {
            address: envelope.address(),
            envelope: envelope.to_bytes(),
            tx_hash: [8; 32],
            quote: vec![1, 2, 3],
            data_map: Some(encode_data_map(&map).unwrap()),
            salt: Some(salt),
        };
        let first = write_entry_record(&out, "docs/x", &record).unwrap();
        assert_eq!(
            first,
            dir.path()
                .join("album.records")
                .join("docs")
                .join("x.record")
        );
        let second = write_entry_record(&out, "docs/x", &record).unwrap();
        assert_eq!(
            second,
            dir.path()
                .join("album.records")
                .join("docs")
                .join("x-2.record")
        );
        assert_eq!(ant_core::datamap_file::read_record(&first).unwrap(), record);
        assert_eq!(
            ant_core::datamap_file::read_record(&second).unwrap(),
            record
        );
        // Nothing is written beside the manifest but the records folder.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["album.records"]);
    }

    #[test]
    fn a_failed_build_says_where_its_records_are_only_when_some_were_saved() {
        let root = Path::new("album.records");
        let record = |saved: bool| SavedRecord {
            path: "a.bin".into(),
            address: [1; 32],
            record: saved.then(|| root.join("a.bin.record")),
            checked: false,
            problem: None,
        };
        assert_eq!(saved_records_message(&[], root), "");
        assert_eq!(saved_records_message(&[record(false)], root), "");
        assert_eq!(
            saved_records_message(&[record(false), record(true)], root),
            format!(
                "; the records of the files uploaded are in {}",
                root.display()
            )
        );
    }

    #[test]
    fn public_file_spec_parses_with_and_without_path() {
        let hex64 = "ab".repeat(32);
        let (addr, path) = parse_public_file(&hex64).unwrap();
        assert_eq!(addr, [0xab; 32]);
        assert_eq!(path, None);
        for scheme in ["darwin://", "ant://"] {
            let (addr, path) = parse_public_file(&format!("{scheme}{hex64}=docs/a.pdf")).unwrap();
            assert_eq!(addr, [0xab; 32]);
            assert_eq!(path.as_deref(), Some("docs/a.pdf"));
        }
        assert!(parse_public_file("nope").is_err());
    }

    fn one_entry_manifest() -> Manifest {
        Manifest {
            name: Some("pack".into()),
            torrent: None,
            entries: vec![ant_core::data::ManifestEntry {
                path: Some("a.bin".into()),
                size: Some(10),
                source: ContentRef::Public { address: [3; 32] },
            }],
        }
    }

    /// Links are printed as `darwin://manifest/...` and files written as
    /// `.darwin`; upstream's `ant://manifest/...` links and `.ant` files
    /// still load.
    #[test]
    fn links_and_files_are_named_darwin_and_upstreams_still_load() {
        let manifest = one_entry_manifest();
        let (link, _) = make_link(&manifest).unwrap();
        assert!(link.starts_with("darwin://manifest/"), "{link}");
        assert_eq!(load_manifest(&link).unwrap(), manifest);
        let payload = link.strip_prefix("darwin://manifest/").unwrap();
        assert_eq!(
            load_manifest(&format!("ant://manifest/{payload}")).unwrap(),
            manifest
        );

        let dir = tempfile::tempdir().unwrap();
        let written = dir.path().join(manifest_filename_for(Some("pack")));
        assert_eq!(written.file_name().unwrap(), "pack.darwin");
        write_manifest(&manifest, &written, false).unwrap();
        assert_eq!(load_manifest(written.to_str().unwrap()).unwrap(), manifest);
        let upstream = dir.path().join("pack.ant");
        std::fs::copy(&written, &upstream).unwrap();
        assert_eq!(load_manifest(upstream.to_str().unwrap()).unwrap(), manifest);

        // A file link is not a manifest link, in either scheme.
        for file_link in [
            format!("darwin://{}", "ab".repeat(32)),
            format!("ant://{}", "ab".repeat(32)),
        ] {
            let error = load_manifest(&file_link).unwrap_err().to_string();
            assert!(error.contains("darwin file download"), "{error}");
        }
    }

    #[test]
    fn network_and_wallet_needs() {
        let create_offline = ManifestAction::Create {
            paths: vec![],
            output: None,
            name: None,
            compact: false,
            choices: EnvelopeChoices::default(),
            follow_symlinks: false,
            public_files: vec!["ab".repeat(32)],
            embed_public: vec![],
            torrent_hashes: vec![],
            merkle: false,
            no_merkle: false,
            overwrite: false,
            link: false,
        };
        assert!(!create_offline.needs_network());
        assert!(!create_offline.needs_wallet());
        let show = ManifestAction::Show {
            source: "x.ant".into(),
        };
        assert!(!show.needs_network());
        let download = ManifestAction::Download {
            source: "x.ant".into(),
            output: None,
            selection: vec![],
            overwrite: false,
            concurrency: DEFAULT_CONCURRENCY,
        };
        assert!(download.needs_network());
        assert!(!download.needs_wallet());
        for yes in [false, true] {
            let compact = ManifestAction::Export {
                source: "x.ant".into(),
                output: None,
                compact: true,
                yes,
                overwrite: false,
                link: false,
            };
            assert!(compact.needs_network());
            assert_eq!(compact.needs_wallet(), yes, "only --yes publishes");
        }
    }

    #[derive(Debug, clap::Parser)]
    struct TestManifestCli {
        #[command(subcommand)]
        action: ManifestAction,
    }

    /// `export --compact` needs the network, and a wallet only with
    /// `--yes`/`-y`, which publishes; the help says what `--yes` publishes
    /// and that it gets no envelope.
    #[test]
    fn export_compact_needs_a_wallet_only_to_publish() {
        use clap::Parser;
        for (argv, publishes) in [
            (&["test", "export", "x.darwin", "--compact"][..], false),
            (&["test", "export", "x.darwin", "--compact", "--yes"], true),
            (&["test", "export", "x.darwin", "--compact", "-y"], true),
        ] {
            let action = TestManifestCli::try_parse_from(argv)
                .expect("parses")
                .action;
            assert!(
                matches!(action, ManifestAction::Export { compact: true, .. }),
                "{argv:?}"
            );
            assert!(action.needs_network(), "{argv:?}");
            assert_eq!(action.needs_wallet(), publishes, "{argv:?}");
            action.validate().unwrap();
        }
        let plain = TestManifestCli::try_parse_from(["test", "export", "x.darwin"])
            .unwrap()
            .action;
        assert!(!plain.needs_network());
        assert!(!plain.needs_wallet());
        let help = TestManifestCli::try_parse_from(["test", "export", "--help"])
            .expect_err("--help")
            .to_string();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains("--yes"), "{help}");
        assert!(help.contains("darwin file upload --public"), "{help}");
        assert!(
            help.contains("`darwin file upload --visibility unlisted`"),
            "{help}"
        );
        assert!(
            help.contains("published as plain chunks instead (paid), with no envelope"),
            "{help}"
        );
    }

    /// A plan with a file no address reads goes ahead only with `--yes`.
    /// Without it, the error names each such file, the standard way to make
    /// it readable, and what `--yes` does instead; the warning `--yes`
    /// prints says the published data maps get no envelope.
    #[test]
    fn compaction_decision_names_the_standard_way_and_publishes_only_with_yes() {
        use ant_core::data::{EmbeddedEntry, PublicForm};
        let entry = |index: u8, name: &str, form| EmbeddedEntry {
            index: usize::from(index),
            name: name.into(),
            address: [index; 32],
            form,
        };
        let free = CompactPlan {
            already_public: vec![entry(0, "a.bin", Some(PublicForm::UnlistedEnvelope))],
            needs_publish: vec![],
        };
        for yes in [false, true] {
            compaction_decision(&free, yes).unwrap();
            compaction_decision(&CompactPlan::default(), yes).unwrap();
        }

        let mut not_free = free;
        not_free.needs_publish = vec![entry(1, "docs/b.bin", None), entry(2, "c.bin", None)];
        compaction_decision(&not_free, true).unwrap();
        let error = compaction_decision(&not_free, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("2 file(s) have no public address yet:"),
            "{error}"
        );
        assert!(error.contains("\n  docs/b.bin\n  c.bin\n"), "{error}");
        assert!(
            error.contains(
                "Make each readable with `darwin file upload --visibility unlisted <FILE>` \
                 (no --name, --content-type or --hide) and export again, or pass --yes"
            ),
            "{error}"
        );
        assert!(
            error.ends_with(
                "publish their data maps as plain chunks: paid, and with no envelope, so no \
                 payment record, listing or .record."
            ),
            "{error}"
        );

        let warning = plain_publish_warning(&not_free);
        assert!(
            warning.starts_with(
                "publishing the data maps of 2 file(s) as plain chunks, with no envelope: no \
                 payment record, listing or .record"
            ),
            "{warning}"
        );
        assert!(warning.ends_with(":\n  docs/b.bin\n  c.bin"), "{warning}");
    }

    /// `create` takes the merkle flags as `darwin file upload` does:
    /// `--no-merkle` parses, hidden from the help; `--merkle` parses, to be
    /// refused when the command runs (file.rs's `payment_mode`), so every
    /// file is paid per chunk; and the two together are a mistake.
    #[test]
    fn create_takes_the_merkle_flags_as_file_upload_does() {
        use clap::Parser;
        let merkle_flags = |flags: &[&str]| {
            let mut argv = vec!["test", "create", "photos"];
            argv.extend_from_slice(flags);
            match TestManifestCli::try_parse_from(argv).map(|cli| cli.action) {
                Ok(ManifestAction::Create {
                    merkle, no_merkle, ..
                }) => Ok((merkle, no_merkle)),
                Ok(_) => panic!("expected create"),
                Err(e) => Err(e.kind()),
            }
        };
        assert_eq!(merkle_flags(&[]), Ok((false, false)));
        assert_eq!(merkle_flags(&["--no-merkle"]), Ok((false, true)));
        assert_eq!(merkle_flags(&["--merkle"]), Ok((true, false)));
        assert_eq!(
            merkle_flags(&["--merkle", "--no-merkle"]),
            Err(clap::error::ErrorKind::ArgumentConflict)
        );
        assert!(payment_mode(true).is_err());
        assert!(matches!(payment_mode(false), Ok(PaymentMode::Single)));
        let help = TestManifestCli::try_parse_from(["test", "create", "--help"])
            .expect_err("--help")
            .to_string();
        assert!(
            help.contains("--merkle") && !help.contains("--no-merkle"),
            "{help}"
        );
    }

    /// The upload options a `create photos` command line asks for.
    fn create_options(flags: &[&str]) -> Result<EnvelopeOptions, String> {
        use clap::Parser;
        let mut argv = vec!["test", "create", "photos"];
        argv.extend_from_slice(flags);
        let cli = TestManifestCli::try_parse_from(argv).map_err(|e| e.to_string())?;
        match cli.action {
            ManifestAction::Create { choices, .. } => {
                create_upload_options(&choices).map_err(|e| e.to_string())
            }
            _ => panic!("expected create"),
        }
    }

    /// The upload options a `darwin file upload photo.jpg` command line asks
    /// for.
    fn file_upload_options(flags: &[&str]) -> Result<EnvelopeOptions, String> {
        use super::super::file::FileAction;
        use clap::Parser;
        #[derive(Debug, clap::Parser)]
        struct TestFileCli {
            #[command(subcommand)]
            action: FileAction,
        }
        let mut argv = vec!["test", "upload", "photo.jpg"];
        argv.extend_from_slice(flags);
        let cli = TestFileCli::try_parse_from(argv).map_err(|e| e.to_string())?;
        match cli.action {
            FileAction::Upload { choices, .. } => choices.options().map_err(|e| e.to_string()),
            _ => panic!("expected upload"),
        }
    }

    /// With no flags, a manifest's files are uploaded as `darwin file
    /// upload` uploads one: in a private envelope that shows all five
    /// payment fields.
    #[test]
    fn create_defaults_to_private_envelopes_with_every_field_shown() {
        use ant_core::ant_listings::ShownFields;
        use ant_core::data::Visibility;
        let options = create_options(&[]).unwrap();
        assert_eq!(options, EnvelopeOptions::private());
        assert_eq!(options.shown, ShownFields::ALL);
        assert!(!options.readable && !options.in_index);
        assert_eq!(options, file_upload_options(&[]).unwrap());
        assert_eq!(
            options.into_visibility(),
            Visibility::Envelope(EnvelopeOptions::private())
        );
    }

    /// `--public` is the unlisted envelope, as `darwin file upload --public`
    /// is, not a plain data map chunk.
    #[test]
    fn create_public_is_the_unlisted_envelope_file_upload_public_is() {
        use ant_core::data::Visibility;
        let public = create_options(&["--public"]).unwrap();
        assert_eq!(public, EnvelopeOptions::unlisted());
        assert_eq!(public, file_upload_options(&["--public"]).unwrap());
        assert_eq!(
            public.into_visibility(),
            Visibility::Envelope(EnvelopeOptions::unlisted())
        );
    }

    /// `create` takes the envelope choices of `darwin file upload`, with the
    /// same meaning and the same conflicts.
    #[test]
    fn create_takes_file_uploads_envelope_choices() {
        use ant_core::data::Visibility;
        for flags in [
            &["--visibility", "private"][..],
            &["--visibility", "unlisted"],
            &["--visibility", "listed"],
            &["--readable", "yes"],
            &["--readable", "no"],
            &["--readable", "yes", "--index", "yes"],
            &["--index", "yes"],
            &["--hide", "tx-hash,quote"],
            &["--hide", "block", "--hide", "log-index"],
            &["--hide", "all"],
            &["--hide", "all", "--public"],
            &["--hide", "all", "--index", "yes"],
        ] {
            assert_eq!(
                create_options(flags).unwrap(),
                file_upload_options(flags).unwrap(),
                "{flags:?}"
            );
        }
        assert_eq!(
            create_options(&["--visibility", "listed"]).unwrap(),
            EnvelopeOptions::listed()
        );
        assert_eq!(
            create_options(&["--readable", "yes"]).unwrap(),
            EnvelopeOptions::unlisted()
        );
        let dated = create_options(&["--index", "yes"]).unwrap();
        assert!(!dated.readable && dated.in_index);
        // Hiding everything on an upload not in the index stores no
        // envelope: private, or a plain data map chunk when readable.
        assert_eq!(
            create_options(&["--hide", "all"])
                .unwrap()
                .into_visibility(),
            Visibility::Private
        );
        assert_eq!(
            create_options(&["--hide", "all", "--public"])
                .unwrap()
                .into_visibility(),
            Visibility::Public
        );
        // The conflicts of `darwin file upload`.
        for flags in [
            &["--readable", "maybe"][..],
            &["--visibility", "listed", "--readable", "no"],
            &["--visibility", "listed", "--index", "no"],
            &["--public", "--index", "yes"],
            &["--public", "--readable", "yes"],
            &["--public", "--visibility", "listed"],
            &["--hide", "wallet"],
        ] {
            assert!(create_options(flags).is_err(), "{flags:?}");
            assert!(file_upload_options(flags).is_err(), "{flags:?}");
        }
    }

    /// A manifest of private uploads is not recorded in the upload history:
    /// their data maps stay in their records and the manifest file. One of
    /// readable uploads, or one that uploads nothing, is recorded.
    #[test]
    fn a_manifest_of_private_uploads_is_not_recorded() {
        for flags in [
            &[][..],
            &["--hide", "all"],
            &["--index", "yes"],
            &["--visibility", "private"],
        ] {
            assert!(
                uploads_are_private(&create_options(flags).unwrap(), true),
                "{flags:?}"
            );
            assert!(!uploads_are_private(&create_options(flags).unwrap(), false));
        }
        for flags in [
            &["--public"][..],
            &["--visibility", "listed"],
            &["--readable", "yes"],
            &["--public", "--hide", "all"],
        ] {
            assert!(
                !uploads_are_private(&create_options(flags).unwrap(), true),
                "{flags:?}"
            );
        }
        assert_eq!(history_record(true, &one_entry_manifest()), None);
    }

    /// `--name` names the manifest; a manifest's files get no envelope
    /// metadata, and `create` has no `--content-type`.
    #[test]
    fn create_name_is_the_manifest_name() {
        use clap::Parser;
        let cli = TestManifestCli::try_parse_from(["test", "create", "photos", "--name", "album"])
            .unwrap();
        let ManifestAction::Create { name, choices, .. } = cli.action else {
            panic!("expected create");
        };
        assert_eq!(name.as_deref(), Some("album"));
        let options = create_upload_options(&choices).unwrap();
        assert!(options.metadata.is_empty());
        assert_eq!(options, EnvelopeOptions::private());
        assert!(TestManifestCli::try_parse_from([
            "test",
            "create",
            "photos",
            "--content-type",
            "text/plain"
        ])
        .is_err());
    }

    /// Bad choices are refused by `validate`, which `main` calls before it
    /// reads SECRET_KEY or joins the network.
    #[test]
    fn create_rejects_bad_hide_before_the_network() {
        use clap::Parser;
        let action = |argv: &[&str]| TestManifestCli::try_parse_from(argv).unwrap().action;
        let error = action(&["test", "create", "photos", "--hide", "tx_hash"])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(error.contains("tx_hash"), "{error}");
        assert!(
            action(&["test", "create", "photos", "--hide", "tx-hash,quote"])
                .validate()
                .is_ok()
        );
        assert!(action(&["test", "create", "photos"]).validate().is_ok());
        // A create that uploads nothing is checked the same way.
        let address = "ab".repeat(32);
        assert!(action(&[
            "test",
            "create",
            "--public-file",
            &address,
            "--hide",
            "nope"
        ])
        .validate()
        .is_err());
        assert!(action(&["test", "list"]).validate().is_ok());
        assert!(action(&["test", "show", "x.darwin"]).validate().is_ok());
    }

    /// `--embed-public` embeds a plain data map, adds a readable envelope by
    /// its address without embedding its data map, and refuses a private
    /// file's envelope, before anything is uploaded or paid.
    #[test]
    fn embed_public_embeds_plain_maps_and_adds_envelopes_by_address() {
        use ant_core::ant_listings::{self_encryption, Metadata, ShownFields};
        let (map, _) = self_encryption::encrypt(bytes::Bytes::from(vec![6u8; 4_000])).unwrap();
        let record = |bytes: Vec<u8>| (compute_address(&bytes), bytes);

        // A plain data map, as a readable upload with no envelope stores it.
        let (address, bytes) = record(rmp_serde::to_vec(&map).unwrap());
        match embed_choice(&address, &bytes) {
            EmbedChoice::Embed(embedded) => assert!(embedded == map),
            other => panic!("expected the data map to embed, got {other:?}"),
        }

        // Readable envelopes, in the index or not, whatever they show and
        // whatever their metadata.
        for in_index in [false, true] {
            for shown in [ShownFields::ALL, ShownFields::NONE] {
                for metadata in [
                    Metadata::default(),
                    Metadata {
                        content_type: Some("text/plain".into()),
                        name: Some("notes.txt".into()),
                    },
                ] {
                    let envelope = Envelope::readable(&map, metadata, shown, in_index).unwrap();
                    let (address, bytes) = record(envelope.to_bytes());
                    assert_eq!(address, envelope.address());
                    assert!(
                        matches!(
                            embed_choice(&address, &bytes),
                            EmbedChoice::ByEnvelopeAddress
                        ),
                        "in_index {in_index}, shown {shown:?}"
                    );
                }
            }
        }

        // A private file's envelope withholds its data map, listed or not.
        for in_index in [false, true] {
            let envelope = Envelope::withheld(
                &map,
                &[3; 32],
                Metadata::default(),
                ShownFields::ALL,
                in_index,
            )
            .unwrap();
            let (address, bytes) = record(envelope.to_bytes());
            assert!(matches!(
                embed_choice(&address, &bytes),
                EmbedChoice::Withheld
            ));
        }

        // Bytes that don't hash to the address, that are no data map, or a
        // damaged envelope.
        let envelope = Envelope::readable(&map, Metadata::default(), ShownFields::ALL, false)
            .unwrap()
            .to_bytes();
        assert!(matches!(
            embed_choice(&[0; 32], &envelope),
            EmbedChoice::Invalid(_)
        ));
        let (address, bytes) = record(b"not a data map".to_vec());
        assert!(matches!(
            embed_choice(&address, &bytes),
            EmbedChoice::Invalid(_)
        ));
        let (address, bytes) = record(envelope[..8].to_vec());
        assert!(is_envelope(&bytes));
        assert!(matches!(
            embed_choice(&address, &bytes),
            EmbedChoice::Invalid(_)
        ));
    }
}
