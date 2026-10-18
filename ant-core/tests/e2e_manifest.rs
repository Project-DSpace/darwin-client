//! ADR-0006 end-to-end: build a manifest from a directory, share it as a
//! `.darwin` file and as a manifest link, and extract it against a real
//! in-process testnet with Anvil payments.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::fs;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use ant_core::ant_listings::Envelope;
use ant_core::data::{
    apply_compaction, data_map_address, embeddable_data_map, embedded_len, extract_manifest,
    forget_upload_record, manifest_link, parse_link, plan_compaction, read_manifest_file,
    record_upload, write_manifest_file, BuildEvent, BuildOptions, Client, ContentRef, EntryStatus,
    EnvelopeOptions, ExtractOptions, Link, ListingChain, Manifest, ManifestBuilder, ManifestEntry,
    ManifestError, PaymentMode, PublicForm, ReferenceMode, Visibility, MAX_EMBEDDED_ROOT_MAP_BYTES,
};
use self_encryption::{shrink_data_map, ChunkInfo, DataMap};
use serial_test::serial;
use support::{test_client_config, MiniTestnet, DEFAULT_NODE_COUNT};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use xor_name::XorName;

/// Payload size for each test file; comfortably above the self-encryption
/// minimum and below one chunk so uploads stay quick.
const FILE_BYTES: usize = 2048;
/// Chunk infos in a synthetic root map small enough to embed.
const SMALL_ROOT_CHUNKS: usize = 8;
/// Chunk infos in a synthetic root map whose encoding exceeds the cap.
const LARGE_ROOT_CHUNKS: usize = 2_000;
/// A file large enough that self-encryption splits it into more than three
/// chunks, so its upload publishes a shrunk DataMap.
const SHRUNK_FILE_BYTES: usize = 13 * 1024 * 1024;

/// A root DataMap with `chunks` synthetic infos; the hashes need not exist
/// on the network because only the map's own encoding and shrinking matter.
fn synthetic_root(chunks: usize, seed: u8) -> DataMap {
    DataMap::new(
        (0..chunks)
            .map(|index| ChunkInfo {
                index,
                dst_hash: XorName([seed.wrapping_add(index as u8); 32]),
                src_hash: XorName([seed.wrapping_mul(3).wrapping_add(index as u8); 32]),
                src_size: FILE_BYTES,
            })
            .collect(),
    )
}

/// Shrink `root` as an upload would and store its wrapper records.
async fn shrink_and_store(client: &Client, root: DataMap) -> DataMap {
    let (child, wrapper_chunks) = shrink_data_map(root, |_, _| Ok(())).expect("shrink");
    assert!(child.is_child());
    for chunk in wrapper_chunks {
        client
            .chunk_put(chunk.content)
            .await
            .expect("store wrapper record");
    }
    child
}

async fn setup() -> (Client, MiniTestnet) {
    let testnet = MiniTestnet::start(DEFAULT_NODE_COUNT).await;
    let node = testnet.node(3).expect("Node 3 should exist");
    let client = Client::from_node(Arc::clone(&node), test_client_config())
        .with_wallet(testnet.wallet().clone());
    (client, testnet)
}

fn write_tree(root: &Path) {
    fs::create_dir_all(root.join("docs")).unwrap();
    fs::write(root.join("a.bin"), vec![0x11u8; FILE_BYTES]).unwrap();
    fs::write(root.join("docs/b.bin"), vec![0x22u8; FILE_BYTES]).unwrap();
    fs::write(root.join("docs/c.bin"), vec![0x33u8; FILE_BYTES]).unwrap();
}

fn extract_options(output: &Path, selection: Vec<String>) -> ExtractOptions {
    ExtractOptions {
        output_root: output.to_path_buf(),
        selection,
        overwrite: false,
        concurrency: NonZeroUsize::new(2).unwrap(),
        cancel: CancellationToken::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn manifest_round_trips_through_file_and_link() {
    let (client, testnet) = setup().await;

    let source = TempDir::new().unwrap();
    write_tree(source.path());

    // A public file added by address, uploaded separately: in the unlisted
    // envelope the public shortcut stores, whose address reads the file.
    let extra = source.path().join("..").join("extra.bin");
    fs::write(&extra, vec![0x44u8; FILE_BYTES]).unwrap();
    let extra_upload = client
        .file_upload_public_with_mode(&extra, PaymentMode::Auto)
        .await
        .expect("public upload");
    let extra_address = extra_upload.data_map_address.expect("public address");
    let extra_envelope = extra_upload.envelope.expect("an envelope");
    assert_eq!(extra_envelope.address(), extra_address);
    if extra_envelope.proof.is_some() {
        forget_upload_record(&extra_address).expect("forget the kept record");
    }

    let mut builder = ManifestBuilder::new(
        &client,
        BuildOptions {
            name: Some("tree".into()),
            torrent: None,
            reference_mode: ReferenceMode::Embedded,
            visibility: Visibility::Private,
            payment_mode: PaymentMode::Auto,
            follow_symlinks: false,
            cancel: CancellationToken::new(),
        },
    );
    builder.add_directory(source.path(), None).unwrap();
    builder
        .add_public(
            extra_address,
            Some("extra/extra.bin".into()),
            Some(FILE_BYTES as u64),
        )
        .unwrap();
    let built = builder.finish(None).await.expect("build manifest");
    assert_eq!(built.files_uploaded, 3);
    assert_eq!(built.total_to_upload, 3);
    assert_eq!(built.manifest.entries.len(), 4);
    assert!(built
        .manifest
        .entries
        .iter()
        .filter(|e| e.path.as_deref() != Some("extra/extra.bin"))
        .all(|e| matches!(e.source, ContentRef::Embedded { .. })));

    // Manifest file round trip.
    let ant_path = source.path().join("..").join("tree.darwin");
    write_manifest_file(&ant_path, &built.manifest, true).unwrap();
    let from_file = read_manifest_file(&ant_path).unwrap();
    assert_eq!(from_file, built.manifest);

    // Manifest link round trip.
    let link = manifest_link(&built.manifest).unwrap();
    let from_link = match parse_link(&link).unwrap() {
        Link::Manifest(m) => m,
        Link::File(_) => panic!("expected manifest link"),
    };
    assert_eq!(from_link, built.manifest);

    // Full extraction.
    let out = TempDir::new().unwrap();
    let report = extract_manifest(
        &client,
        &from_link,
        &extract_options(out.path(), vec![]),
        None,
    )
    .await
    .expect("extract");
    assert_eq!(report.written(), 4, "{:?}", report.entries);
    assert_eq!(report.failed(), 0);
    assert_eq!(
        fs::read(out.path().join("a.bin")).unwrap(),
        vec![0x11u8; FILE_BYTES]
    );
    assert_eq!(
        fs::read(out.path().join("docs/b.bin")).unwrap(),
        vec![0x22u8; FILE_BYTES]
    );
    assert_eq!(
        fs::read(out.path().join("docs/c.bin")).unwrap(),
        vec![0x33u8; FILE_BYTES]
    );
    assert_eq!(
        fs::read(out.path().join("extra/extra.bin")).unwrap(),
        vec![0x44u8; FILE_BYTES]
    );

    // Selective extraction by directory prefix into a fresh root.
    let partial = TempDir::new().unwrap();
    let report = extract_manifest(
        &client,
        &from_file,
        &extract_options(partial.path(), vec!["docs".into()]),
        None,
    )
    .await
    .expect("partial extract");
    assert_eq!(report.written(), 2);
    assert!(!partial.path().join("a.bin").exists());
    assert!(partial.path().join("docs/b.bin").exists());

    // Existing targets fail per entry without overwrite and nothing else is
    // touched; with overwrite they are replaced.
    let report = extract_manifest(
        &client,
        &from_file,
        &extract_options(out.path(), vec![]),
        None,
    )
    .await
    .expect("second extract runs");
    assert_eq!(report.failed(), 4);
    assert!(report
        .entries
        .iter()
        .all(|e| matches!(&e.status, EntryStatus::Failed { error } if error.contains("exists"))));
    let mut overwrite = extract_options(out.path(), vec!["a.bin".into()]);
    overwrite.overwrite = true;
    let report = extract_manifest(&client, &from_file, &overwrite, None)
        .await
        .expect("overwrite extract");
    assert_eq!(report.written(), 1);

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn failed_build_keeps_completed_uploads_for_history_and_extraction() {
    let (client, testnet) = setup().await;
    let source = TempDir::new().unwrap();

    for remove in [false, true] {
        let first = source.path().join("first.bin");
        let later = source.path().join("later.bin");
        let expected = vec![if remove { 0x92 } else { 0x91 }; FILE_BYTES];
        fs::write(&first, &expected).unwrap();
        fs::write(&later, vec![0x93; FILE_BYTES]).unwrap();

        let mut builder = ManifestBuilder::new(&client, BuildOptions::default());
        builder.add_file(&first, "first.bin".into()).unwrap();
        builder.add_file(&later, "later.bin".into()).unwrap();
        builder
            .add_public([9; 32], Some("existing.bin".into()), None)
            .unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let sabotage = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if matches!(event, BuildEvent::FileStarted { index: 0, .. }) {
                    // Preflight has passed. The first file still needs real
                    // network/payment work before the next file is read.
                    if remove {
                        fs::remove_file(&later).unwrap();
                    } else {
                        fs::write(&later, [0x01]).unwrap();
                    }
                }
            }
        });
        let error = builder.finish(Some(tx)).await.unwrap_err();
        sabotage.await.unwrap();
        let ManifestError::BuildFailed {
            path,
            cause,
            partial,
        } = error
        else {
            panic!("expected a recoverable build failure");
        };
        assert_eq!(path, "later.bin");
        if remove {
            assert!(matches!(*cause, ManifestError::Io(_)));
        } else {
            assert!(matches!(*cause, ManifestError::Data(_)));
        }
        assert_eq!(partial.files_uploaded, 1);
        assert_eq!(partial.total_to_upload, 2);
        assert!(!partial.cancelled);
        assert_eq!(partial.manifest.entries.len(), 2);
        assert!(partial
            .manifest
            .entries
            .iter()
            .any(|entry| entry.path.as_deref() == Some("first.bin")));
        assert!(!partial
            .manifest
            .entries
            .iter()
            .any(|entry| entry.path.as_deref() == Some("later.bin")));
        // The paid file's envelope, uploaded by default as a private one,
        // comes back with the partial result, so its record can be saved.
        assert_eq!(partial.envelopes.len(), 1);
        assert_eq!(partial.envelopes[0].path, "first.bin");
        let envelope = &partial.envelopes[0].envelope;
        assert!(envelope.salt.is_some());
        assert!(envelope.proof.is_some(), "{:?}", envelope.proof_problem);
        forget_upload_record(&envelope.address()).expect("forget the kept record");

        let history = TempDir::new().unwrap();
        let record = record_upload(history.path(), &partial.manifest, None).unwrap();
        let recovered = read_manifest_file(&record.path).unwrap();
        let out = TempDir::new().unwrap();
        let report = extract_manifest(
            &client,
            &recovered,
            &extract_options(out.path(), vec!["first.bin".into()]),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.written(), 1);
        assert_eq!(fs::read(out.path().join("first.bin")).unwrap(), expected);
    }

    // References do not count toward the original upload total, including
    // when cancellation happens before the first upload starts.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut builder = ManifestBuilder::new(
        &client,
        BuildOptions {
            cancel,
            ..Default::default()
        },
    );
    let first = source.path().join("first.bin");
    builder.add_file(&first, "first.bin".into()).unwrap();
    builder.add_file(&first, "second.bin".into()).unwrap();
    builder
        .add_public([9; 32], Some("existing.bin".into()), None)
        .unwrap();
    let cancelled = builder.finish(None).await.unwrap();
    assert!(cancelled.cancelled);
    assert_eq!(cancelled.files_uploaded, 0);
    assert_eq!(cancelled.total_to_upload, 2);
    assert_eq!(cancelled.manifest.entries.len(), 1);
    assert!(cancelled.envelopes.is_empty());

    drop(client);
    testnet.teardown().await;
}

/// A manifest's files are uploaded as a file upload uploads one: by default
/// each in a private envelope that shows every payment field, with a record
/// that checks out against the chain; readable with the unlisted envelope,
/// and then named in a compact manifest by the envelope's address.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_build_stores_each_file_in_an_envelope_with_its_record() {
    let (client, testnet) = setup().await;
    let chain = ListingChain::new(testnet.evm_network()).expect("chain reader");

    let source = TempDir::new().unwrap();
    write_tree(source.path());
    let mut builder = ManifestBuilder::new(&client, BuildOptions::default());
    builder.add_directory(source.path(), None).unwrap();
    let built = builder.finish(None).await.expect("build");
    assert_eq!(built.files_uploaded, 3);
    let mut paths: Vec<&str> = built.envelopes.iter().map(|e| e.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["a.bin", "docs/b.bin", "docs/c.bin"]);
    for uploaded in &built.envelopes {
        let envelope = &uploaded.envelope;
        assert!(envelope.salt.is_some(), "a private envelope has a salt");
        assert!(envelope.proof_checked, "{:?}", envelope.proof_problem);
        let record = envelope.proof.clone().expect("a record");
        assert_eq!(record.address, envelope.address());
        let proven = chain
            .check_proof(&record)
            .await
            .expect("the record checks out against the chain");
        // The record reveals the data map the manifest embeds.
        let entry = built
            .manifest
            .entries
            .iter()
            .find(|entry| entry.path.as_deref() == Some(uploaded.path.as_str()))
            .expect("the file's entry");
        let ContentRef::Embedded { data_map } = &entry.source else {
            panic!("a private file's data map is embedded");
        };
        assert!(proven.data_map.as_ref() == Some(data_map));
        // The stored envelope withholds the data map and shows every
        // payment field.
        let chunk = client
            .chunk_get(&envelope.address())
            .await
            .expect("fetch")
            .expect("the envelope is stored");
        let stored = Envelope::from_bytes(&chunk.content).expect("an envelope");
        assert!(stored.is_withheld());
        assert_eq!(stored.flags(), EnvelopeOptions::private().flags());
        forget_upload_record(&envelope.address()).expect("forget the kept record");
    }
    let out = TempDir::new().unwrap();
    let report = extract_manifest(
        &client,
        &built.manifest,
        &extract_options(out.path(), vec![]),
        None,
    )
    .await
    .expect("extract");
    assert_eq!(report.written(), 3, "{:?}", report.entries);
    assert_eq!(
        fs::read(out.path().join("docs/c.bin")).unwrap(),
        vec![0x33u8; FILE_BYTES]
    );

    // `--public --compact`: the file is readable at its unlisted envelope's
    // address, and the manifest names it by that address.
    let readable = TempDir::new().unwrap();
    fs::write(readable.path().join("e.bin"), vec![0x5au8; FILE_BYTES]).unwrap();
    let mut builder = ManifestBuilder::new(
        &client,
        BuildOptions {
            reference_mode: ReferenceMode::Compact,
            visibility: EnvelopeOptions::unlisted().into_visibility(),
            ..Default::default()
        },
    );
    builder.add_directory(readable.path(), None).unwrap();
    let built = builder.finish(None).await.expect("build readable");
    let [uploaded] = built.envelopes.as_slice() else {
        panic!("one envelope: {:?}", built.envelopes);
    };
    let address = uploaded.envelope.address();
    assert_eq!(
        built.manifest.entries[0].source,
        ContentRef::Public { address }
    );
    let record = uploaded.envelope.proof.clone().expect("a record");
    chain
        .check_proof(&record)
        .await
        .expect("the record checks out against the chain");
    let chunk = client
        .chunk_get(&address)
        .await
        .expect("fetch")
        .expect("the envelope is stored");
    assert_eq!(
        Envelope::from_bytes(&chunk.content).unwrap().flags(),
        EnvelopeOptions::unlisted().flags()
    );
    forget_upload_record(&address).expect("forget the kept record");
    let out = TempDir::new().unwrap();
    let report = extract_manifest(
        &client,
        &built.manifest,
        &extract_options(out.path(), vec![]),
        None,
    )
    .await
    .expect("extract by the envelope address");
    assert_eq!(report.written(), 1, "{:?}", report.entries);
    assert_eq!(
        fs::read(out.path().join("e.bin")).unwrap(),
        vec![0x5au8; FILE_BYTES]
    );

    drop(client);
    testnet.teardown().await;
}

/// A file uploaded in a readable envelope, unlisted or listed, is added to a
/// manifest by the envelope's address, as `darwin manifest create
/// --embed-public` adds it, and extracts to its bytes. Its plain data map's
/// address, an embedded entry's identity, holds nothing.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn readable_envelopes_added_by_their_address_extract() {
    let (client, testnet) = setup().await;
    let source = TempDir::new().unwrap();
    let mut builder = ManifestBuilder::new(&client, BuildOptions::default());
    let mut expected = Vec::new();
    for (name, options, fill) in [
        ("unlisted.bin", EnvelopeOptions::unlisted(), 0x61u8),
        ("listed.bin", EnvelopeOptions::listed(), 0x62),
    ] {
        let path = source.path().join(name);
        fs::write(&path, vec![fill; FILE_BYTES]).unwrap();
        let result = client
            .file_upload_with_visibility_and_progress(
                &path,
                PaymentMode::Single,
                Visibility::Envelope(options.clone()),
                None,
            )
            .await
            .expect("upload");
        let envelope = result.envelope.clone().expect("an envelope");
        let address = envelope.address();
        assert_eq!(result.data_map_address, Some(address));
        // What `--embed-public` reads at the address: the readable envelope.
        let chunk = client
            .chunk_get(&address)
            .await
            .expect("fetch")
            .expect("the envelope is stored");
        let stored = Envelope::from_bytes(&chunk.content).expect("an envelope");
        assert!(!stored.is_withheld());
        assert_eq!(stored.flags(), options.flags());
        assert!(client
            .chunk_get(&data_map_address(&result.data_map).unwrap())
            .await
            .expect("fetch")
            .is_none());
        if envelope.proof.is_some() {
            forget_upload_record(&address).expect("forget the kept record");
        }
        builder
            .add_public(address, Some(name.into()), None)
            .unwrap();
        expected.push((name, vec![fill; FILE_BYTES]));
    }
    let built = builder.finish(None).await.expect("build");
    assert_eq!(built.files_uploaded, 0);
    assert!(built
        .manifest
        .entries
        .iter()
        .all(|entry| matches!(entry.source, ContentRef::Public { .. })));
    let out = TempDir::new().unwrap();
    let report = extract_manifest(
        &client,
        &built.manifest,
        &extract_options(out.path(), vec![]),
        None,
    )
    .await
    .expect("extract");
    assert_eq!(report.written(), 2, "{:?}", report.entries);
    for (name, bytes) in expected {
        assert_eq!(fs::read(out.path().join(name)).unwrap(), bytes, "{name}");
    }

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn compact_mode_uses_public_addresses_only_when_the_datamap_is_on_the_network() {
    let (client, testnet) = setup().await;

    let source = TempDir::new().unwrap();
    fs::write(source.path().join("private.bin"), vec![0x55u8; FILE_BYTES]).unwrap();
    fs::write(source.path().join("public.bin"), vec![0x66u8; FILE_BYTES]).unwrap();

    // Make public.bin's DataMap public ahead of time, as a plain DataMap
    // chunk (the public shortcut stores an envelope instead); private.bin
    // stays private, so compact mode must embed it rather than publish it.
    client
        .file_upload_with_visibility_and_progress(
            &source.path().join("public.bin"),
            PaymentMode::Auto,
            Visibility::Public,
            None,
        )
        .await
        .expect("pre-publish");

    let mut builder = ManifestBuilder::new(
        &client,
        BuildOptions {
            name: None,
            torrent: None,
            reference_mode: ReferenceMode::Compact,
            visibility: Visibility::Private,
            payment_mode: PaymentMode::Auto,
            follow_symlinks: false,
            cancel: CancellationToken::new(),
        },
    );
    builder.add_directory(source.path(), None).unwrap();
    let built = builder.finish(None).await.expect("build");

    let kind_of = |name: &str| {
        built
            .manifest
            .entries
            .iter()
            .find(|e| e.path.as_deref() == Some(name))
            .map(|e| e.source.kind())
            .unwrap()
    };
    assert_eq!(kind_of("public.bin"), "public");
    assert_eq!(kind_of("private.bin"), "embedded");

    // The default mode embeds every DataMap, even when the files are
    // uploaded as public in the same run.
    let mut embedded_builder = ManifestBuilder::new(
        &client,
        BuildOptions {
            name: None,
            torrent: None,
            reference_mode: ReferenceMode::Embedded,
            visibility: Visibility::Public,
            payment_mode: PaymentMode::Auto,
            follow_symlinks: false,
            cancel: CancellationToken::new(),
        },
    );
    embedded_builder.add_directory(source.path(), None).unwrap();
    let embedded = embedded_builder.finish(None).await.expect("build embedded");
    assert!(embedded
        .manifest
        .entries
        .iter()
        .all(|e| e.source.kind() == "embedded"));

    let out = TempDir::new().unwrap();
    let report = extract_manifest(
        &client,
        &built.manifest,
        &extract_options(out.path(), vec![]),
        None,
    )
    .await
    .expect("extract");
    assert_eq!(report.written(), 2, "{:?}", report.entries);
    assert_eq!(
        fs::read(out.path().join("public.bin")).unwrap(),
        vec![0x66u8; FILE_BYTES]
    );

    drop(client);
    testnet.teardown().await;
}

/// `export --compact` finds a file readable in the envelope
/// `darwin file upload --public` stores (unlisted), or in a listed one, at
/// the address the embedded data map alone gives, and compacts the entry to
/// that address, which extracts. A private file is readable by no address:
/// the plan is not free, which the CLI refuses, compaction leaves the entry
/// embedded, and nothing is published, so its plain data map address still
/// holds nothing.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn compact_export_finds_readable_envelopes_and_publishes_nothing() {
    let (client, testnet) = setup().await;

    let source = TempDir::new().unwrap();
    let files = [
        ("listed.bin", 0x66u8),
        ("private.bin", 0x77),
        ("unlisted.bin", 0x88),
    ];
    for (name, fill) in files {
        fs::write(source.path().join(name), vec![fill; FILE_BYTES]).unwrap();
    }

    // Two of the files are made readable first, as `darwin file upload
    // --public` and `--visibility listed` upload them.
    let mut readable = Vec::new();
    for (name, options) in [
        ("unlisted.bin", EnvelopeOptions::unlisted()),
        ("listed.bin", EnvelopeOptions::listed()),
    ] {
        let result = client
            .file_upload_with_visibility_and_progress(
                &source.path().join(name),
                PaymentMode::Single,
                options.into_visibility(),
                None,
            )
            .await
            .expect("readable upload");
        let envelope = result.envelope.expect("an envelope");
        if envelope.proof.is_some() {
            forget_upload_record(&envelope.address()).expect("forget the kept record");
        }
        readable.push((name, envelope.address()));
    }

    // A private manifest of all three embeds every data map.
    let mut builder = ManifestBuilder::new(&client, BuildOptions::default());
    builder.add_directory(source.path(), None).unwrap();
    let built = builder.finish(None).await.expect("build");
    for uploaded in &built.envelopes {
        forget_upload_record(&uploaded.envelope.address()).expect("forget the kept record");
    }
    let manifest = built.manifest;
    assert!(manifest
        .entries
        .iter()
        .all(|e| e.source.kind() == "embedded"));
    let index_of = |name: &str| {
        manifest
            .entries
            .iter()
            .position(|e| e.path.as_deref() == Some(name))
            .unwrap()
    };

    let plan = plan_compaction(&client, &manifest, &CancellationToken::new())
        .await
        .expect("plan");
    assert_eq!(plan.already_public.len(), 2, "{plan:?}");
    for (name, address) in &readable {
        let planned = plan
            .already_public
            .iter()
            .find(|e| e.index == index_of(name))
            .expect("planned as already public");
        assert_eq!(planned.address, *address, "{name}: the envelope's address");
        let form = if *name == "unlisted.bin" {
            PublicForm::UnlistedEnvelope
        } else {
            PublicForm::ListedEnvelope
        };
        assert_eq!(planned.form, Some(form), "{name}");
    }
    let [private] = plan.needs_publish.as_slice() else {
        panic!("only the private file needs publishing: {plan:?}");
    };
    assert_eq!(private.index, index_of("private.bin"));
    assert_eq!(private.form, None);
    assert!(!plan.is_free(), "the CLI refuses a plan that isn't free");

    let compacted = apply_compaction(&manifest, &plan).unwrap();
    for (name, address) in &readable {
        assert_eq!(
            compacted.entries[index_of(name)].source,
            ContentRef::Public { address: *address },
            "{name}"
        );
    }
    assert_eq!(
        compacted.entries[index_of("private.bin")].source,
        manifest.entries[index_of("private.bin")].source,
        "the private file stays embedded"
    );

    // Nothing was published: no data map is stored on its own.
    for entry in &manifest.entries {
        let address = entry.source.content_address().unwrap();
        assert!(
            !client.chunk_exists(&address).await.expect("check"),
            "{:?}: a plain data map was stored",
            entry.path
        );
    }

    let out = TempDir::new().unwrap();
    let report = extract_manifest(
        &client,
        &compacted,
        &extract_options(out.path(), vec![]),
        None,
    )
    .await
    .expect("extract compacted");
    assert_eq!(report.written(), 3, "{:?}", report.entries);
    for (name, fill) in files {
        assert_eq!(
            fs::read(out.path().join(name)).unwrap(),
            vec![fill; FILE_BYTES],
            "{name}"
        );
    }

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn embedding_uses_the_root_map_only_when_it_is_small_enough() {
    let (client, testnet) = setup().await;

    // A small file's shrunk map resolves back to its root for embedding, so a
    // reader starts on data chunks with no wrapper-record fetches.
    let small_root = synthetic_root(SMALL_ROOT_CHUNKS, 0x10);
    assert!(embedded_len(&small_root).unwrap() <= MAX_EMBEDDED_ROOT_MAP_BYTES);
    let small_child = shrink_and_store(&client, small_root.clone()).await;
    let embedded = embeddable_data_map(&client, &small_child)
        .await
        .expect("resolve small");
    assert!(!embedded.is_child());
    assert_eq!(embedded, small_root);
    // Embedding the root does not change the entry's identity.
    assert_eq!(
        data_map_address(&embedded).unwrap(),
        data_map_address(&small_child).unwrap()
    );

    // A huge file's root exceeds the cap, so the shrunk map is embedded.
    let large_root = synthetic_root(LARGE_ROOT_CHUNKS, 0x40);
    assert!(embedded_len(&large_root).unwrap() > MAX_EMBEDDED_ROOT_MAP_BYTES);
    let large_child = shrink_and_store(&client, large_root).await;
    let embedded = embeddable_data_map(&client, &large_child)
        .await
        .expect("resolve large");
    assert!(embedded.is_child());
    assert_eq!(embedded, large_child);

    // A map that is already a root is returned without any fetch.
    let root = synthetic_root(SMALL_ROOT_CHUNKS, 0x70);
    assert_eq!(embeddable_data_map(&client, &root).await.unwrap(), root);

    drop(client);
    testnet.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn embedded_root_identity_is_the_published_address() {
    let (client, testnet) = setup().await;

    let source = TempDir::new().unwrap();
    let file = source.path().join("big.bin");
    let bytes: Vec<u8> = (0..SHRUNK_FILE_BYTES).map(|i| (i % 251) as u8).collect();
    fs::write(&file, &bytes).unwrap();

    let result = client
        .file_upload_with_visibility_and_progress(
            &file,
            PaymentMode::Auto,
            Visibility::Public,
            None,
        )
        .await
        .expect("public upload");
    let published = result.data_map_address.expect("public address");
    assert!(result.data_map.is_child(), "the upload must shrink its map");

    // The address derived locally from the root, by re-shrinking it, is the
    // address the upload published.
    let root = embeddable_data_map(&client, &result.data_map)
        .await
        .expect("resolve root");
    assert!(!root.is_child());
    assert_eq!(data_map_address(&root).unwrap(), published);
    assert_eq!(data_map_address(&result.data_map).unwrap(), published);

    // An entry embedding that root, as a private upload of the same bytes
    // records it, is found already public by compaction.
    let manifest = Manifest {
        name: None,
        torrent: None,
        entries: vec![ManifestEntry {
            path: Some("big.bin".into()),
            size: None,
            source: ContentRef::Embedded { data_map: root },
        }],
    };
    let plan = plan_compaction(&client, &manifest, &CancellationToken::new())
        .await
        .expect("plan");
    assert!(plan.is_free(), "{plan:?}");
    assert_eq!(plan.already_public.len(), 1);
    assert_eq!(plan.already_public[0].address, published);
    assert_eq!(plan.already_public[0].form, Some(PublicForm::Plain));

    // The link form carries the shrunk map and keeps the identity.
    let link = manifest.link_form().unwrap();
    let ContentRef::Embedded { data_map } = &link.entries[0].source else {
        panic!("link form keeps the entry embedded");
    };
    assert_eq!(data_map, &result.data_map);

    drop(client);
    testnet.teardown().await;
}
