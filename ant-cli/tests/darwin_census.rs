//! Census of the places in ant-core and ant-cli that store or pay, choose
//! how an upload is shown or paid, build a wallet, replace the binary, or
//! decode a data map, and of the node manager's erasures and of what it
//! calls outside its own code.
//!
//! Each test reads the production source of both crates (`../ant-core/src`
//! and `src`; the erasure and boundary censuses only the node manager's part
//! of it) and
//! fails when a mention of a name it counts appears anywhere its reviewed
//! list doesn't name, or when a listed site holds more or fewer mentions than
//! listed. A change that adds such a path, a merge from upstream among them,
//! then fails CI until someone has looked at it and listed it with its
//! reason.
//!
//! The rules the reasons answer to:
//!
//! - every upload path of this client's own commands and file shortcuts
//!   stores an envelope (payment record, listing, `.record` proof), private
//!   by default with every payment field shown;
//! - raw paths (single chunks, plain data maps, the library's raw building
//!   blocks, the browser core) stay available, documented as carrying no
//!   envelope: "raw, by the caller's choice: no envelope";
//! - payments are made per chunk in the network's own token, with paid
//!   quotes read back from the vault, through the chain-bound wallet;
//! - self-update and the node manager stay off in this build;
//! - no path of the node manager deletes a node's data folder: the darwin
//!   CLI's `darwin node reset` is off, and the storage-node image's manager
//!   (`darwin-nodes`) has no reset and no disk-pressure eviction.
//!
//! The source is read as tokens, so layout, comments and string literals
//! (except those a list names in double quotes) make no difference.
//! Test-only code is left out: items under a `cfg` that is false in a
//! production build (`test`, `feature = "test-utils"`), `#[test]` functions,
//! and module files declared only that way. Mentions count, not only calls,
//! so an import under another name is counted too.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One reviewed site: the file, the site (`Type::function`, `function` or
/// `<module>`), the name counted, how many times it is mentioned there, and
/// why it is there.
type Site = (
    &'static str,
    &'static str,
    &'static str,
    usize,
    &'static str,
);

// ---------------------------------------------------------------------------
// What is counted, and the reviewed sites
// ---------------------------------------------------------------------------

/// Stores and payments: every way to pay for or store a record. The browser
/// core's paying exports (uploadPublicFile, uploadStagedPublicFile,
/// uploadRecords, createPointer, updatePointer, transferPointer,
/// storePaidPointer) each take the page's `pay_for_quotes` callback, so they
/// are counted by it.
const STORES: Counting = &[
    (None, "pay_for_quotes"),
    (None, "pay_for_merkle_tree"),
    (None, "pay_for_merkle_multi_batch"),
    (None, "pay_for_storage*"),
    (None, "pay_for_record*"),
    (None, "batch_pay"),
    (None, "batch_upload_chunks*"),
    (None, "upload_records"),
    (None, "upload_records_then"),
    (None, "chunk_put*"),
    (None, "data_map_store"),
    (None, "pointer_put*"),
    (None, "store_pointer"),
    (None, "finalize_upload*"),
    (None, "finalize_resume*"),
    (None, "finalize_chunk"),
    (None, "publish_data_maps"),
    (Some("ManifestBuilder"), "new"),
    (None, "file_upload*"),
    (None, "data_upload*"),
    (None, "*_prepare_upload*"),
    (None, "ChunkPutRequest"),
    (None, "PointerPutRequest"),
];

/// Choices of how an upload is shown and paid.
const CHOICES: Counting = &[
    (Some("Visibility"), "Private"),
    (Some("Visibility"), "Public"),
    (Some("Visibility"), "default"),
    (Some("BuildOptions"), "default"),
    (None, "hiding"),
    (Some("ShownFields"), "NONE"),
    (None, "into_visibility"),
    (Some("PaymentMode"), "Auto"),
    (Some("PaymentMode"), "Merkle"),
    (None, "\"auto\""),
    (None, "\"merkle\""),
];

/// Wallets and signers.
const WALLETS: Counting = &[
    (Some("Wallet"), "new"),
    (None, "new_from_private_key"),
    (None, "new_with_random_wallet"),
    (None, "EthereumWallet"),
    (None, "PrivateKeySigner"),
    (None, "LocalSigner"),
    (None, "with_chain_id"),
];

/// Replacing the running binary.
const SELF_UPDATE: Counting = &[
    (None, "check_for_update"),
    (None, "perform_update"),
    (None, "self_replace"),
];

/// Decoding data maps (and anything else in MessagePack or JSON), with
/// self-encryption's own decoder too.
const DECODES: Counting = &[
    (None, "decode_map_record"),
    (Some("DataMap"), "from_bytes"),
    (Some("rmp_serde"), "from_slice"),
    (Some("rmp_serde"), "from_read"),
    (Some("serde_json"), "from_slice"),
];

/// Erasures in the node manager's code (see [`NODE_MANAGER`]): every deletion
/// of a file or folder, and every reset of all node state.
const ERASES: Counting = &[
    (None, "remove_dir_all"),
    (None, "remove_dir"),
    (None, "remove_file"),
    (Some("node"), "reset"),
    (Some("client"), "reset"),
];

// Reasons, shared by the sites below.

const ENVELOPE_CLI: &str = "darwin's own upload command: every file gets an envelope from \
    EnvelopeOptions, private by default with all five payment fields shown, paid per chunk.";
const ENVELOPE_LIB: &str = "The library's file shortcuts: an envelope from EnvelopeOptions, \
    private by default with all five payment fields shown, paid per chunk.";
const FINALIZE: &str = "Finishes a prepared file upload with the envelope chosen when it was \
    prepared; paid per chunk through the upload coordinator, which reads paid quotes back.";
const PER_CHUNK: &str = "Per-chunk payment in the network's token through the client's \
    chain-bound wallet; paid quotes are read back from the vault and occupied ones quoted again.";
const RAW_CHUNK_PUT: &str = "raw, by the caller's choice: no envelope. `darwin chunk put` \
    stores one raw chunk; its help names `darwin file upload` as the standard way. Paid per chunk \
    with the read-back.";
const RAW_CHUNK: &str = "raw, by the caller's choice: no envelope. A single chunk, paid per \
    chunk with the read-back.";
const RAW_DATA: &str = "raw, by the caller's choice: no envelope. data_upload stores a plain \
    data map; its docs name file_upload as the standard path. Paid per chunk with the read-back.";
const RAW_PAYMENT: &str = "raw, by the caller's choice: no envelope. A raw building block that \
    pays given quotes per chunk with no read-back; batch_upload_chunks is the path that reads back.";
const COMPACT_PUBLISH: &str = "raw, by the caller's choice: no envelope. `manifest export \
    --compact --yes` publishes data maps of entries with no public address as plain chunks, after \
    saying they get no envelope; readable envelopes are reused for free. Paid per chunk with the \
    read-back.";
const POINTER: &str = "Pointer write: paid per chunk in the network's token, the paid quote \
    read back; a pointer record has no data map, so no envelope.";
const MERKLE: &str = "Upstream's merkle (batch) payment: kept in the library, chosen by no \
    darwin command (they pay per chunk, and --merkle is refused), and refused by the network's \
    nodes.";
const BROWSER: &str = "raw, by the caller's choice: no envelope. The browser core stores a \
    plain data map; the page's wallet pays each quote (pay_for_quotes is its callback), per chunk \
    by default; there is no read-back of paid quotes in the browser yet.";
const BROWSER_POINTER: &str = "The browser core's pointer writes: the page's wallet pays the \
    quote (pay_for_quotes is its callback); a pointer record has no envelope.";
const BROWSER_WIRE: &str = "The browser transport admits and sends a pointer PUT the browser \
    core built and paid; it stores nothing itself.";
const IMPORT: &str = "An import or re-export of a listed path; the calls are listed where \
    they are made.";

const VISIBILITY: &str = "Maps the chosen visibility (an envelope, or the raw Private and \
    Public of the library's building blocks) to what is stored; the defaults stay envelopes.";
const CLI_VISIBILITY: &str = "darwin's upload flags made into an envelope choice: private by \
    default with all five payment fields shown.";
const SHOWN_NONE: &str = "Compares with no payment field shown: fields are hidden only when \
    asked (--hide), and what the listing then shows is said.";
const MERKLE_MODE: &str = "Upstream's merkle mode in the library and cost estimate; no darwin \
    command chooses it, and PaymentMode::default() is Single.";
const BROWSER_MODE: &str = "The browser's payment mode names, mapped in one tested native \
    function; the browser's default is Single.";

const CHAIN_WALLET: &str = "The one wallet: built from the configured key and bound to the \
    configured chain's id.";
const DEVNET_WALLET: &str = "A funded wallet on a local devnet's Anvil chain (the devnet \
    feature), for tests.";

const UPDATE_OFF: &str = "Unreachable: `darwin update` refuses (SELF_UPDATE is false) before \
    it checks or replaces anything.";

const NETWORK_MAP: &str = "A data map read from the network, decoded through \
    decode_map_record, which bounds it.";
const BOUNDED_MAP: &str = "decode_map_record itself: the decode of data maps read from the \
    network, but for the producer's bounded root-map read (ROOT_MAP).";
const ROOT_MAP: &str = "The root map of a listed file whose data map is shrunk once, decrypted \
    from at most 3 chunks, each checked against its address and decrypted no further than the \
    size the map declares for it, within MAX_ROOT_MAP_BYTES; only its size is kept.";
const LOCAL_FILE: &str = "Decodes a local file this client wrote (a datamap file, upload \
    state, a snapshot, earlier listings output), not network bytes.";
const EMBED_LOCAL: &str = "Decodes a data map from a local manifest file the user gave, to \
    decide whether to embed it.";
const RESET: &str = "node::reset deletes every node's data and log folders: reached only from \
    `darwin node reset` and the darwin CLI daemon's POST /api/v1/reset, both off (NODE_MANAGER is \
    false); darwin-nodes reaches neither.";
const RESET_COMMAND: &str = "Unreachable: `darwin node reset` (imported here, or calling the \
    reset), and `darwin node` refuses every command before it runs (NODE_MANAGER is false). \
    darwin-nodes has no reset.";
const RESET_ROUTE: &str = "POST /api/v1/reset, served by the darwin CLI's daemon only (`darwin \
    node daemon run`, off); the daemon of darwin-nodes (server::start_image_manager) has no such \
    route.";
const DOWNLOAD_LEFTOVERS: &str = "A download's temporary archive and duplicate extracted copies, \
    in the download cache (<data dir>/bin), never a node's folder; reached only from `darwin node \
    add` with a download source (off). darwin-nodes downloads nothing.";
const DAEMON_FILES: &str = "The daemon's own port and pid files, when it stops or is found gone.";
const MANAGER_LOG: &str = "darwin-nodes' own log files (<prefix>.*.log in its --log-path folder), \
    never a node's: closed files past the family's 50 MiB cap or a month old, and every closed one \
    at the disk's full line, so its log never fills the disk the nodes share.";
const NODE_PID: &str = "A node's pid file (<data dir>/node.pid), once its process has exited; the \
    node's data stays.";

const CORE_ERROR: &str = "ant-core's error and result types (error.rs): values, not actions; \
    they delete nothing.";
const CONFIG_DIRS: &str = "ant-core's config module, for the platform's data and config \
    directories (data_dir, config_dir): paths only, nothing deleted. Any other config function \
    the manager calls is listed here on its own.";
const CHANNEL: &str = "channel::version_matches_channel compares a node version with an upgrade \
    channel; it reads and deletes nothing.";
const NODE_ADD_PROGRESS: &str = "The darwin CLI's progress bar for `darwin node add`, off \
    (NODE_MANAGER is false); it draws a bar and deletes nothing.";
const DEVNET_CLIENT: &str = "LocalDevnet (the devnet feature: tests and local devnets; neither \
    darwin binary links it) hands back a client of the devnet it started, and its error type. \
    The client stores and reads records; what it deletes is its own caches, never a node's \
    folder.";

const NOT_A_MAP: &str = "Decodes a quote, proof, peer record or receipt, not a data map.";

const STORE_SITES: &[Site] = &[
    (
        "ant-cli/src/commands/data/chunk.rs",
        "ChunkAction::execute",
        "chunk_put",
        1,
        RAW_CHUNK_PUT,
    ),
    (
        "ant-cli/src/commands/data/file.rs",
        "handle_file_upload",
        "file_upload_with_visibility_and_progress",
        2,
        ENVELOPE_CLI,
    ),
    (
        "ant-cli/src/commands/data/manifest.rs",
        "<module>",
        "publish_data_maps",
        1,
        IMPORT,
    ),
    (
        "ant-cli/src/commands/data/manifest.rs",
        "create",
        "ManifestBuilder::new",
        1,
        ENVELOPE_CLI,
    ),
    (
        "ant-cli/src/commands/data/manifest.rs",
        "export_compact",
        "publish_data_maps",
        2,
        COMPACT_PUBLISH,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "<module>",
        "pay_for_quotes",
        6,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "BrowserNetworkClient::prepare_pay_and_store_records",
        "pay_for_quotes",
        1,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "BrowserNetworkClient::prepare_pay_and_store_records",
        "upload_records",
        1,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "BrowserNetworkClient::upload_public_file",
        "pay_for_quotes",
        1,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "BrowserNetworkClient::upload_public_file_inner",
        "pay_for_quotes",
        1,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "BrowserNetworkClient::upload_records",
        "pay_for_quotes",
        1,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "BrowserNetworkClient::upload_staged_public_file",
        "pay_for_quotes",
        1,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport.rs",
        "BrowserNetworkClient::upload_staged_public_file_inner",
        "pay_for_quotes",
        1,
        BROWSER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "<module>",
        "pay_for_quotes",
        5,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::create_pointer",
        "pay_for_quotes",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::store_paid_pointer",
        "pointer_put_paid",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::store_pointer",
        "pay_for_quotes",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::store_pointer",
        "pointer_put_paid",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::transfer_pointer",
        "pay_for_quotes",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::update_pointer",
        "pay_for_quotes",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::write_pointer",
        "pay_for_quotes",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/pointer.rs",
        "BrowserNetworkClient::write_pointer",
        "store_pointer",
        1,
        BROWSER_POINTER,
    ),
    (
        "ant-core/src/browser/wasm_transport/shared.rs",
        "Admission::of",
        "PointerPutRequest",
        2,
        BROWSER_WIRE,
    ),
    (
        "ant-core/src/browser/wasm_transport/shared.rs",
        "SharedNetworkAdapter::request",
        "PointerPutRequest",
        2,
        BROWSER_WIRE,
    ),
    (
        "ant-core/src/data/client/batch.rs",
        "Client::batch_pay",
        "pay_for_quotes",
        1,
        RAW_PAYMENT,
    ),
    (
        "ant-core/src/data/client/batch.rs",
        "Client::batch_upload_chunks",
        "batch_upload_chunks_with_events",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/batch.rs",
        "Client::batch_upload_chunks_with_events",
        "upload_records",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/batch.rs",
        "Client::store_paid_chunks_with_events",
        "chunk_put_to_close_group",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/batch.rs",
        "SingleNodeQuotePayment::pay",
        "pay_for_quotes",
        1,
        RAW_PAYMENT,
    ),
    (
        "ant-core/src/data/client/chunk.rs",
        "<module>",
        "ChunkPutRequest",
        1,
        IMPORT,
    ),
    (
        "ant-core/src/data/client/chunk.rs",
        "Client::chunk_put",
        "chunk_put_to_close_group",
        2,
        RAW_CHUNK,
    ),
    (
        "ant-core/src/data/client/chunk.rs",
        "Client::chunk_put",
        "pay_for_storage",
        1,
        RAW_CHUNK,
    ),
    (
        "ant-core/src/data/client/chunk.rs",
        "Client::chunk_put",
        "pay_for_record",
        1,
        RAW_CHUNK,
    ),
    (
        "ant-core/src/data/client/chunk.rs",
        "Client::chunk_put_with_proof",
        "ChunkPutRequest",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/chunk.rs",
        "Client::finalize_chunk",
        "chunk_put_to_close_group",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/chunk.rs",
        "Client::spawn_chunk_put",
        "chunk_put_with_proof",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/data.rs",
        "Client::data_map_store",
        "chunk_put",
        1,
        RAW_CHUNK,
    ),
    (
        "ant-core/src/data/client/data.rs",
        "Client::data_prepare_upload",
        "data_prepare_upload_with_visibility",
        1,
        RAW_DATA,
    ),
    (
        "ant-core/src/data/client/data.rs",
        "Client::data_upload",
        "batch_upload_chunks",
        1,
        RAW_DATA,
    ),
    (
        "ant-core/src/data/client/data.rs",
        "Client::data_upload_with_mode",
        "upload_records",
        1,
        RAW_DATA,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_prepare_upload",
        "file_prepare_upload_with_progress",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_prepare_upload_with_progress",
        "file_prepare_upload_with_mode",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_prepare_upload_with_visibility",
        "file_prepare_upload_with_progress",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_upload",
        "file_upload_with_mode",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_upload_public_with_mode",
        "file_upload_with_visibility_and_progress",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_upload_public_with_progress",
        "file_upload_with_visibility_and_progress",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_upload_with_mode",
        "file_upload_with_progress",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_upload_with_progress",
        "file_upload_with_visibility_and_progress",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_resume",
        "finalize_resume_with_progress",
        1,
        FINALIZE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_upload",
        "finalize_upload_with_progress",
        1,
        FINALIZE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_upload_merkle",
        "finalize_upload_merkle_with_progress",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_upload_merkle_multi",
        "finalize_upload_merkle_multi_with_progress",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_upload_merkle_multi_resumable",
        "finalize_upload_merkle_multi_resumable_with_progress",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_upload_merkle_with_progress",
        "finalize_upload_merkle_multi_with_progress",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_upload_resumable",
        "finalize_upload_resumable_with_progress",
        1,
        FINALIZE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::upload_file",
        "upload_records",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::upload_file",
        "upload_records_then",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::upload_merkle_from_spill",
        "chunk_put_to_close_group",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/merkle.rs",
        "Client::pay_for_merkle_batch",
        "pay_for_merkle_multi_batch",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/merkle.rs",
        "Client::pay_for_merkle_single_batch",
        "pay_for_merkle_tree",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/payment.rs",
        "Client::pay_for_storage",
        "pay_for_storage_split",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/payment.rs",
        "Client::pay_for_storage_split",
        "pay_for_storage_once",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/payment.rs",
        "Client::pay_for_storage_split",
        "pay_for_record",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/payment.rs",
        "Client::pay_for_record",
        "pay_for_record_in",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/payment.rs",
        "Client::settle_record",
        "pay_for_storage_once",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "<module>",
        "PointerPutRequest",
        2,
        IMPORT,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_create",
        "pointer_put",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_put",
        "pay_for_storage_split",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_put",
        "pay_for_record",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_put",
        "pointer_put_paid_unchecked",
        2,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_put_once",
        "PointerPutRequest",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_put_paid",
        "pointer_put_paid_unchecked",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_put_paid_unchecked",
        "pointer_put_once",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_transfer",
        "pointer_put",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::pointer_update",
        "pointer_put",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/pointer.rs",
        "Client::send_pointer_put",
        "PointerPutRequest",
        1,
        POINTER,
    ),
    (
        "ant-core/src/data/client/upload.rs",
        "Client::store_upload_merkle",
        "chunk_put_to_close_group",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/client/upload.rs",
        "MemoryUploadAdapter::pay",
        "pay_for_quotes",
        1,
        PER_CHUNK,
    ),
    (
        "ant-core/src/data/client/upload.rs",
        "MemoryUploadAdapter::pay_merkle",
        "pay_for_merkle_tree",
        1,
        MERKLE,
    ),
    (
        "ant-core/src/data/manifest/build.rs",
        "ManifestBuilder::finish",
        "file_upload_with_visibility_and_progress",
        1,
        ENVELOPE_LIB,
    ),
    (
        "ant-core/src/data/manifest/compact.rs",
        "publish_data_maps",
        "data_map_store",
        1,
        COMPACT_PUBLISH,
    ),
    (
        "ant-core/src/data/mod.rs",
        "<module>",
        "publish_data_maps",
        1,
        IMPORT,
    ),
];

const CHOICE_SITES: &[Site] = &[
    (
        "ant-cli/src/commands/data/file.rs",
        "handle_file_cost",
        "into_visibility",
        1,
        CLI_VISIBILITY,
    ),
    (
        "ant-cli/src/commands/data/file.rs",
        "handle_file_upload",
        "into_visibility",
        1,
        CLI_VISIBILITY,
    ),
    (
        "ant-cli/src/commands/data/file.rs",
        "private_envelope_note",
        "ShownFields::NONE",
        1,
        SHOWN_NONE,
    ),
    (
        "ant-cli/src/commands/data/manifest.rs",
        "create",
        "into_visibility",
        1,
        CLI_VISIBILITY,
    ),
    (
        "ant-core/src/browser/payment_mode.rs",
        "payment_mode_named",
        "\"auto\"",
        1,
        BROWSER_MODE,
    ),
    (
        "ant-core/src/browser/payment_mode.rs",
        "payment_mode_named",
        "\"merkle\"",
        1,
        BROWSER_MODE,
    ),
    (
        "ant-core/src/browser/payment_mode.rs",
        "payment_mode_named",
        "PaymentMode::Auto",
        1,
        BROWSER_MODE,
    ),
    (
        "ant-core/src/browser/payment_mode.rs",
        "payment_mode_named",
        "PaymentMode::Merkle",
        1,
        BROWSER_MODE,
    ),
    (
        "ant-core/src/data/client/data.rs",
        "Client::data_prepare_upload_with_visibility",
        "Visibility::Private",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/data.rs",
        "Client::data_prepare_upload_with_visibility",
        "Visibility::Public",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/envelope.rs",
        "EnvelopeOptions::into_visibility",
        "Visibility::Private",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/envelope.rs",
        "EnvelopeOptions::into_visibility",
        "Visibility::Public",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/envelope.rs",
        "EnvelopeOptions::warnings",
        "ShownFields::NONE",
        1,
        SHOWN_NONE,
    ),
    (
        "ant-core/src/data/client/envelope.rs",
        "private_shortcut_visibility",
        "into_visibility",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/envelope.rs",
        "public_shortcut_visibility",
        "into_visibility",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/envelope.rs",
        "shown_after_hiding",
        "ShownFields::NONE",
        1,
        SHOWN_NONE,
    ),
    (
        "ant-core/src/data/client/file.rs",
        "Visibility::normalized",
        "into_visibility",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::estimate_upload_cost_with_visibility",
        "PaymentMode::Merkle",
        3,
        MERKLE_MODE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_prepare_upload_with_mode",
        "Visibility::Private",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::file_prepare_upload_with_mode",
        "Visibility::Public",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::finalize_upload_merkle_multi_with_progress",
        "PaymentMode::Merkle",
        1,
        MERKLE_MODE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::upload_file",
        "Visibility::Private",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "Client::upload_file",
        "Visibility::Public",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "assemble_merkle_finalize_outcome",
        "PaymentMode::Merkle",
        2,
        MERKLE_MODE,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "extra_upload_chunk",
        "Visibility::Private",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/file/native.rs",
        "extra_upload_chunk",
        "Visibility::Public",
        1,
        VISIBILITY,
    ),
    (
        "ant-core/src/data/client/merkle.rs",
        "should_use_merkle",
        "PaymentMode::Auto",
        1,
        MERKLE_MODE,
    ),
    (
        "ant-core/src/data/client/merkle.rs",
        "should_use_merkle",
        "PaymentMode::Merkle",
        1,
        MERKLE_MODE,
    ),
    (
        "ant-core/src/data/client/upload.rs",
        "Client::prepare_upload_merkle",
        "PaymentMode::Auto",
        2,
        MERKLE_MODE,
    ),
    (
        "ant-core/src/data/client/upload.rs",
        "Client::prepare_upload_merkle",
        "PaymentMode::Merkle",
        3,
        MERKLE_MODE,
    ),
    (
        "ant-core/src/data/client/upload.rs",
        "Client::store_upload_merkle",
        "PaymentMode::Merkle",
        1,
        MERKLE_MODE,
    ),
];

const WALLET_SITES: &[Site] = &[
    (
        "ant-core/src/config.rs",
        "<module>",
        "EthereumWallet",
        1,
        IMPORT,
    ),
    (
        "ant-core/src/config.rs",
        "<module>",
        "PrivateKeySigner",
        1,
        IMPORT,
    ),
    (
        "ant-core/src/config.rs",
        "wallet",
        "EthereumWallet",
        1,
        CHAIN_WALLET,
    ),
    (
        "ant-core/src/config.rs",
        "wallet",
        "PrivateKeySigner",
        1,
        CHAIN_WALLET,
    ),
    (
        "ant-core/src/config.rs",
        "wallet",
        "Wallet::new",
        1,
        CHAIN_WALLET,
    ),
    (
        "ant-core/src/config.rs",
        "wallet",
        "with_chain_id",
        1,
        CHAIN_WALLET,
    ),
    (
        "ant-core/src/node/devnet.rs",
        "LocalDevnet::create_funded_client",
        "new_from_private_key",
        1,
        DEVNET_WALLET,
    ),
];

const SELF_UPDATE_SITES: &[Site] = &[
    (
        "ant-cli/src/commands/update.rs",
        "UpdateArgs::execute",
        "check_for_update",
        1,
        UPDATE_OFF,
    ),
    (
        "ant-cli/src/commands/update.rs",
        "UpdateArgs::execute",
        "perform_update",
        1,
        UPDATE_OFF,
    ),
    (
        "ant-core/src/update.rs",
        "replace_binary",
        "self_replace",
        2,
        UPDATE_OFF,
    ),
];

const ERASE_SITES: &[Site] = &[
    (
        "ant-cli/src/commands/node/mod.rs",
        "<module>",
        "node::reset",
        1,
        RESET_COMMAND,
    ),
    (
        "ant-cli/src/commands/node/reset.rs",
        "ResetArgs::execute",
        "client::reset",
        1,
        RESET_COMMAND,
    ),
    (
        "ant-cli/src/commands/node/reset.rs",
        "ResetArgs::reset_directly",
        "node::reset",
        1,
        RESET_COMMAND,
    ),
    (
        "ant-cli/src/bin/darwin-nodes/log_file.rs",
        "Family::delete_closed_files",
        "remove_file",
        1,
        MANAGER_LOG,
    ),
    (
        "ant-cli/src/bin/darwin-nodes/log_file.rs",
        "Family::prune",
        "remove_file",
        1,
        MANAGER_LOG,
    ),
    (
        "ant-core/src/node/binary.rs",
        "download_and_extract",
        "remove_file",
        3,
        DOWNLOAD_LEFTOVERS,
    ),
    (
        "ant-core/src/node/daemon/client.rs",
        "stop",
        "remove_file",
        6,
        DAEMON_FILES,
    ),
    (
        "ant-core/src/node/daemon/server.rs",
        "Prepared::serve",
        "remove_file",
        2,
        DAEMON_FILES,
    ),
    (
        "ant-core/src/node/daemon/server.rs",
        "post_reset",
        "node::reset",
        1,
        RESET_ROUTE,
    ),
    (
        "ant-core/src/node/daemon/supervisor.rs",
        "remove_node_pid",
        "remove_file",
        1,
        NODE_PID,
    ),
    (
        "ant-core/src/node/mod.rs",
        "reset",
        "remove_dir_all",
        2,
        RESET,
    ),
];

/// What the node manager's code names outside its own folders, once a file
/// (see [`boundary_census`]).
const BOUNDARY_SITES: &[Site] = &[
    (
        "ant-cli/src/commands/node/add.rs",
        "<file>",
        "darwin::progress::CliProgress",
        1,
        NODE_ADD_PROGRESS,
    ),
    (
        "ant-core/src/node/binary.rs",
        "<file>",
        "ant_core::channel::version_matches_channel",
        1,
        CHANNEL,
    ),
    (
        "ant-core/src/node/binary.rs",
        "<file>",
        "ant_core::config::data_dir",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/binary.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/binary.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/client.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/client.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/forward/config.rs",
        "<file>",
        "ant_core::config",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/daemon/forward/config.rs",
        "<file>",
        "ant_core::config::config_dir",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/daemon/forward/config.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/forward/config.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/forward/es.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/forward/es.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/forward/mod.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/forward/offsets.rs",
        "<file>",
        "ant_core::config",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/daemon/forward/offsets.rs",
        "<file>",
        "ant_core::config::data_dir",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/daemon/forward/offsets.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/forward/tail.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/server.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/server.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/supervisor.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/daemon/supervisor.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/devnet.rs",
        "<file>",
        "ant_core::data::Client",
        1,
        DEVNET_CLIENT,
    ),
    (
        "ant-core/src/node/devnet.rs",
        "<file>",
        "ant_core::data::client::ClientConfig",
        1,
        DEVNET_CLIENT,
    ),
    (
        "ant-core/src/node/devnet.rs",
        "<file>",
        "ant_core::data::error::Error",
        1,
        DEVNET_CLIENT,
    ),
    (
        "ant-core/src/node/devnet.rs",
        "<file>",
        "ant_core::data::error::Result",
        1,
        DEVNET_CLIENT,
    ),
    (
        "ant-core/src/node/mod.rs",
        "<file>",
        "ant_core::config",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/mod.rs",
        "<file>",
        "ant_core::config::data_dir",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/mod.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/mod.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/process/detach.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/process/detach.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/process/spawn.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/process/spawn.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/registry.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/registry.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/types.rs",
        "<file>",
        "ant_core::config",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/types.rs",
        "<file>",
        "ant_core::config::data_dir",
        1,
        CONFIG_DIRS,
    ),
    (
        "ant-core/src/node/types.rs",
        "<file>",
        "ant_core::error::Error",
        1,
        CORE_ERROR,
    ),
    (
        "ant-core/src/node/types.rs",
        "<file>",
        "ant_core::error::Result",
        1,
        CORE_ERROR,
    ),
];

const DECODE_SITES: &[Site] = &[
    (
        "ant-cli/src/commands/data/listings.rs",
        "ListingsArgs::load_earlier",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-cli/src/commands/data/listings.rs",
        "parse_previous",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-cli/src/commands/data/manifest.rs",
        "embed_choice",
        "rmp_serde::from_slice",
        1,
        EMBED_LOCAL,
    ),
    (
        "ant-core/src/browser.rs",
        "decode_address_record",
        "decode_map_record",
        1,
        NETWORK_MAP,
    ),
    (
        "ant-core/src/browser/payment.rs",
        "normalize_commitment_artifact",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
    (
        "ant-core/src/browser/peer_records.rs",
        "peer_record",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
    (
        "ant-core/src/browser/wasm_transport/shared.rs",
        "native_quote_artifact",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
    (
        "ant-core/src/client_engine/files.rs",
        "decode_map",
        "decode_map_record",
        1,
        NETWORK_MAP,
    ),
    (
        "ant-core/src/client_engine/files.rs",
        "decode_map_record",
        "rmp_serde::from_slice",
        1,
        BOUNDED_MAP,
    ),
    (
        "ant-core/src/data/client/adaptive.rs",
        "load_snapshot",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/data/client/data.rs",
        "decode_data_map_chunk",
        "decode_map_record",
        2,
        NETWORK_MAP,
    ),
    (
        "ant-core/src/data/client/listings.rs",
        "paid_quote_hash",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
    (
        "ant-core/src/data/client/listings_feeds.rs",
        "Feeds::open",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/data/client/listings_publish.rs",
        "Files::holds",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/data/client/listings_publish.rs",
        "parse",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/data/client/listings_serve.rs",
        "Producer::start_sizes",
        "rmp_serde::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/data/client/listings_serve.rs",
        "previous_entries",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/data/client/listings_serve.rs",
        "read_root_size",
        "DataMap::from_bytes",
        1,
        ROOT_MAP,
    ),
    (
        "ant-core/src/data/client/merkle.rs",
        "map_merkle_candidate_response",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
    (
        "ant-core/src/data/client/merkle.rs",
        "merkle_candidate_binding_is_valid",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
    (
        "ant-core/src/data/client/quote.rs",
        "classify_quote_response",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
    (
        "ant-core/src/data/client/upload_state.rs",
        "UploadState::restore",
        "rmp_serde::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/datamap_file.rs",
        "read_datamap",
        "rmp_serde::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/datamap_file.rs",
        "read_datamap",
        "serde_json::from_slice",
        1,
        LOCAL_FILE,
    ),
    (
        "ant-core/src/quote_validation.rs",
        "validate_commitment_binding",
        "rmp_serde::from_slice",
        1,
        NOT_A_MAP,
    ),
];

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// One token of Rust source. Comments and whitespace are dropped; literals
/// keep their text so that `cfg` predicates can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Literal(String),
    Lifetime,
    Punct(char),
    /// `::`, `->` or `=>`.
    Joint(&'static str),
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    line: usize,
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Split Rust source into tokens.
#[allow(clippy::too_many_lines)]
fn tokenize(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut tokens = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    while let Some(c) = at(i) {
        let start_line = line;
        let mut push = |tok: Tok| {
            tokens.push(Token {
                tok,
                line: start_line,
            });
        };
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '/' if at(i + 1) == Some('/') => {
                while at(i).is_some_and(|c| c != '\n') {
                    i += 1;
                }
            }
            '/' if at(i + 1) == Some('*') => {
                let mut depth = 0usize;
                while let Some(c) = at(i) {
                    if c == '/' && at(i + 1) == Some('*') {
                        depth += 1;
                        i += 2;
                    } else if c == '*' && at(i + 1) == Some('/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if c == '\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
            }
            '"' => {
                let (text, end) = read_string(&chars, i + 1, &mut line);
                push(Tok::Literal(text));
                i = end;
            }
            '\'' => {
                if at(i + 1) == Some('\\') {
                    // An escaped character: skip the escape, then find the quote.
                    let mut j = i + 3;
                    while at(j).is_some_and(|c| c != '\'') {
                        j += 1;
                    }
                    push(Tok::Literal(String::new()));
                    i = j + 1;
                } else if at(i + 2) == Some('\'') {
                    push(Tok::Literal(String::new()));
                    i += 3;
                } else {
                    i += 1;
                    while at(i).is_some_and(is_ident_continue) {
                        i += 1;
                    }
                    push(Tok::Lifetime);
                }
            }
            c if is_ident_start(c) => {
                if let Some((text, end)) = read_prefixed_literal(&chars, i, &mut line) {
                    push(Tok::Literal(text));
                    i = end;
                    continue;
                }
                // `r#name` is the identifier `name`.
                if c == 'r' && at(i + 1) == Some('#') && at(i + 2).is_some_and(is_ident_start) {
                    i += 2;
                }
                let begin = i;
                while at(i).is_some_and(is_ident_continue) {
                    i += 1;
                }
                push(Tok::Ident(chars[begin..i].iter().collect()));
            }
            c if c.is_ascii_digit() => {
                while let Some(c) = at(i) {
                    let fraction = c == '.' && at(i + 1).is_some_and(|d| d.is_ascii_digit());
                    if is_ident_continue(c) || fraction {
                        i += 1;
                    } else {
                        break;
                    }
                }
                push(Tok::Literal(String::new()));
            }
            ':' if at(i + 1) == Some(':') => {
                push(Tok::Joint("::"));
                i += 2;
            }
            '-' if at(i + 1) == Some('>') => {
                push(Tok::Joint("->"));
                i += 2;
            }
            '=' if at(i + 1) == Some('>') => {
                push(Tok::Joint("=>"));
                i += 2;
            }
            c => {
                push(Tok::Punct(c));
                i += 1;
            }
        }
    }
    tokens
}

/// Read a quoted string whose body starts at `start`, honouring escapes.
/// Returns its text and the index just past the closing quote.
fn read_string(chars: &[char], start: usize, line: &mut usize) -> (String, usize) {
    let mut text = String::new();
    let mut i = start;
    while let Some(&c) = chars.get(i) {
        match c {
            '"' => return (text, i + 1),
            '\\' => {
                if let Some(&escaped) = chars.get(i + 1) {
                    if escaped == '\n' {
                        *line += 1;
                    }
                    text.push(escaped);
                }
                i += 2;
            }
            c => {
                if c == '\n' {
                    *line += 1;
                }
                text.push(c);
                i += 1;
            }
        }
    }
    (text, i)
}

/// A string, byte string, C string or byte literal starting with a prefix
/// at `i` (`b"…"`, `r#"…"#`, `br"…"`, `cr"…"`, `b'…'`), if there is one.
fn read_prefixed_literal(chars: &[char], i: usize, line: &mut usize) -> Option<(String, usize)> {
    let at = |j: usize| chars.get(j).copied();
    let mut j = i;
    if matches!(at(j), Some('b' | 'c')) {
        j += 1;
    }
    if at(j) == Some('r') {
        let mut hashes = 0usize;
        let mut k = j + 1;
        while at(k) == Some('#') {
            hashes += 1;
            k += 1;
        }
        if at(k) != Some('"') {
            return None;
        }
        let body = k + 1;
        let mut end = body;
        while end < chars.len() {
            if chars[end] == '"' && (1..=hashes).all(|h| at(end + h) == Some('#')) {
                let text: String = chars[body..end].iter().collect();
                *line += text.matches('\n').count();
                return Some((text, end + 1 + hashes));
            }
            end += 1;
        }
        let text: String = chars[body..].iter().collect();
        *line += text.matches('\n').count();
        return Some((text, chars.len()));
    }
    if j == i {
        return None;
    }
    match at(j) {
        Some('"') => Some(read_string(chars, j + 1, line)),
        Some('\'') if at(i) == Some('b') => {
            let mut k = j + 1;
            if at(k) == Some('\\') {
                k += 2;
            }
            while at(k).is_some_and(|c| c != '\'') {
                k += 1;
            }
            Some((String::new(), k + 1))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

/// A `cfg` predicate's value in a production build: `test` and the
/// `test-utils` feature are off, anything else may be either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cfg {
    On,
    Off,
    Either,
}

/// Evaluate the `cfg` predicate starting at `*pos`, leaving `*pos` past it.
fn eval_cfg(tokens: &[Token], pos: &mut usize) -> Cfg {
    let Some(Tok::Ident(name)) = tokens.get(*pos).map(|t| &t.tok) else {
        // Not a predicate: skip to the end of this argument.
        while let Some(token) = tokens.get(*pos) {
            if matches!(token.tok, Tok::Punct(',' | ')')) {
                break;
            }
            *pos += 1;
        }
        return Cfg::Either;
    };
    *pos += 1;
    match tokens.get(*pos).map(|t| &t.tok) {
        Some(Tok::Punct('(')) if matches!(name.as_str(), "all" | "any" | "not") => {
            *pos += 1;
            let mut values = Vec::new();
            while let Some(token) = tokens.get(*pos) {
                match token.tok {
                    Tok::Punct(')') => {
                        *pos += 1;
                        break;
                    }
                    Tok::Punct(',') => *pos += 1,
                    _ => {
                        let before = *pos;
                        values.push(eval_cfg(tokens, pos));
                        if *pos == before {
                            *pos += 1;
                        }
                    }
                }
            }
            match name.as_str() {
                "not" => match values.first() {
                    Some(Cfg::On) => Cfg::Off,
                    Some(Cfg::Off) => Cfg::On,
                    _ => Cfg::Either,
                },
                "all" if values.contains(&Cfg::Off) => Cfg::Off,
                "all" if values.iter().all(|v| *v == Cfg::On) => Cfg::On,
                "any" if values.contains(&Cfg::On) => Cfg::On,
                "any" if values.iter().all(|v| *v == Cfg::Off) => Cfg::Off,
                _ => Cfg::Either,
            }
        }
        Some(Tok::Punct('=')) => {
            *pos += 1;
            let value = match tokens.get(*pos).map(|t| &t.tok) {
                Some(Tok::Literal(value)) => value.clone(),
                _ => String::new(),
            };
            *pos += 1;
            if name == "feature" && value == "test-utils" {
                Cfg::Off
            } else {
                Cfg::Either
            }
        }
        _ if name == "test" => Cfg::Off,
        _ => Cfg::Either,
    }
}

/// Whether an attribute (its tokens between the brackets) makes what it is
/// on test-only: a `cfg` that is off in a production build, or a test
/// attribute such as `test` or `tokio::test`.
fn is_test_only_attribute(attr: &[Token]) -> bool {
    let mut path = Vec::new();
    let mut pos = 0;
    while let Some(Tok::Ident(segment)) = attr.get(pos).map(|t| &t.tok) {
        path.push(segment.as_str());
        pos += 1;
        if matches!(attr.get(pos).map(|t| &t.tok), Some(Tok::Joint("::"))) {
            pos += 1;
        } else {
            break;
        }
    }
    match path.as_slice() {
        ["cfg"] if matches!(attr.get(pos).map(|t| &t.tok), Some(Tok::Punct('('))) => {
            pos += 1;
            eval_cfg(attr, &mut pos) == Cfg::Off
        }
        [.., "test"] => true,
        _ => false,
    }
}

/// Index of the bracket closing the one at `open`, or the end of the tokens.
fn matching_close(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0usize;
    for (offset, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return offset;
                }
            }
            _ => {}
        }
    }
    tokens.len()
}

// ---------------------------------------------------------------------------
// Walking a file
// ---------------------------------------------------------------------------

/// What a bracket opened.
#[derive(Debug, Clone)]
enum Frame {
    /// A function body.
    Fn(String),
    /// An `impl` or `trait` block, by the type or trait it names.
    Impl(String),
    /// An inline module.
    Mod(String),
    /// Anything else.
    Other,
}

/// A `mod name;` declaration.
#[derive(Debug, Clone)]
struct ModDecl {
    /// Inline modules it sits in, outermost first.
    within: Vec<String>,
    name: String,
    test_only: bool,
}

/// What one file holds.
#[derive(Debug, Default)]
struct FileScan {
    /// Lines of each counted call, by `(site, call)`.
    calls: BTreeMap<(String, String), Vec<usize>>,
    decls: Vec<ModDecl>,
    /// The whole file is test-only (`#![cfg(test)]` at its top).
    test_only: bool,
}

/// Keywords that start an item or a `let` statement; within one, a comma at
/// the top level does not end it (generics, where clauses).
const ITEM_KEYWORDS: &[&str] = &[
    "const",
    "enum",
    "extern",
    "fn",
    "impl",
    "let",
    "macro_rules",
    "mod",
    "static",
    "struct",
    "trait",
    "type",
    "union",
    "use",
];

/// What a walk counts: every mention of these names, called or not (an
/// import, a type, a path), by name and, where given, the path segment
/// before it (`Type::name`). A name ending in `*` stands for every name that
/// starts with what comes before it, and one also starting with `*` for every
/// name containing what is between. A name in double quotes stands for a
/// string literal with that text. Definitions are not mentions.
type Counting = &'static [(Option<&'static str>, &'static str)];

/// The label a mention of `name`, after `owner::` if it has an owner, is
/// counted under, if `wanted` lists it: the name, after the owner its entry
/// asks for. An entry's name ending in `*` matches every name starting with
/// what comes before it.
fn wanted_label(
    wanted: &[(Option<&str>, &str)],
    owner: Option<&str>,
    name: &str,
) -> Option<String> {
    wanted
        .iter()
        .find(|(wanted_owner, pattern)| {
            let named = match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
                (Some(inner), Some(_)) => name.contains(inner.trim_end_matches('*')),
                (_, Some(prefix)) => name.starts_with(prefix),
                _ => *pattern == name,
            };
            named && wanted_owner.is_none_or(|wanted_owner| owner == Some(wanted_owner))
        })
        .map(|(wanted_owner, _)| {
            wanted_owner.map_or_else(
                || name.to_string(),
                |wanted_owner| format!("{wanted_owner}::{name}"),
            )
        })
}

struct Walker<'a> {
    tokens: &'a [Token],
    counting: Counting,
    stack: Vec<Frame>,
    /// A label for the next `{` opened at this stack depth.
    pending: Option<(Frame, usize)>,
    scan: FileScan,
    /// Set when the walk collects the paths out of the node manager's code
    /// ([`scan_paths`]) rather than names.
    paths: Option<PathScan>,
}

/// Where a file of the node manager's code sits, for resolving its paths,
/// and the aliases its `use` items made so far.
#[derive(Debug, Default)]
struct PathScan {
    /// Its crate: `ant_core`, `darwin` (ant-cli's darwin binary) or
    /// `darwin_nodes`.
    krate: String,
    /// Its module, from its crate's root.
    module: Vec<String>,
    /// Names a `use` brought in that start lower case (modules and
    /// functions), by the crate and path they stand for.
    aliases: BTreeMap<String, (String, Vec<String>)>,
}

impl<'a> Walker<'a> {
    fn new(tokens: &'a [Token], counting: Counting) -> Self {
        Self {
            tokens,
            counting,
            stack: Vec::new(),
            pending: None,
            scan: FileScan::default(),
            paths: None,
        }
    }

    fn tok(&self, pos: usize) -> Option<&Tok> {
        self.tokens.get(pos).map(|t| &t.tok)
    }

    fn ident(&self, pos: usize) -> Option<&str> {
        match self.tok(pos) {
            Some(Tok::Ident(name)) => Some(name.as_str()),
            _ => None,
        }
    }

    fn inline_modules(&self) -> Vec<String> {
        self.stack
            .iter()
            .filter_map(|frame| match frame {
                Frame::Mod(name) => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    /// The site a call at the current depth belongs to.
    fn site(&self) -> String {
        let Some(fn_at) = self
            .stack
            .iter()
            .rposition(|frame| matches!(frame, Frame::Fn(_)))
        else {
            return "<module>".to_string();
        };
        let Some(Frame::Fn(name)) = self.stack.get(fn_at) else {
            return "<module>".to_string();
        };
        let owner = self.stack[..fn_at]
            .iter()
            .rev()
            .find_map(|frame| match frame {
                Frame::Impl(owner) => Some(owner.clone()),
                _ => None,
            });
        owner.map_or_else(|| name.clone(), |owner| format!("{owner}::{name}"))
    }

    fn count(&mut self, call: &str, line: usize) {
        let site = self.site();
        self.scan
            .calls
            .entry((site, call.to_string()))
            .or_default()
            .push(line);
    }

    fn walk(mut self) -> FileScan {
        let mut pos = 0;
        while pos < self.tokens.len() {
            pos = self.step(pos);
        }
        self.scan
    }

    /// Handle the token at `pos`; returns where to continue.
    fn step(&mut self, pos: usize) -> usize {
        let Some(token) = self.tokens.get(pos) else {
            return pos + 1;
        };
        let line = token.line;
        match &token.tok {
            Tok::Punct('#') => return self.attribute(pos),
            Tok::Punct('{') => {
                let depth = self.stack.len();
                let frame = if self.pending.as_ref().is_some_and(|(_, at)| *at == depth) {
                    self.pending.take().map_or(Frame::Other, |(frame, _)| frame)
                } else {
                    Frame::Other
                };
                self.stack.push(frame);
            }
            Tok::Punct('(' | '[') => self.stack.push(Frame::Other),
            Tok::Punct('}' | ')' | ']') => {
                self.stack.pop();
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|(_, at)| *at > self.stack.len())
                {
                    self.pending = None;
                }
            }
            Tok::Punct(';') => {
                if let Some((frame, at)) = self.pending.take() {
                    if at == self.stack.len() {
                        if let Frame::Mod(name) = frame {
                            self.scan.decls.push(ModDecl {
                                within: self.inline_modules(),
                                name,
                                test_only: false,
                            });
                        }
                    } else {
                        self.pending = Some((frame, at));
                    }
                }
            }
            Tok::Ident(name) => {
                let name = name.clone();
                return self.ident_at(pos, &name, line);
            }
            Tok::Literal(text) => {
                let quoted = format!("\"{text}\"");
                if self
                    .counting
                    .iter()
                    .any(|(owner, pattern)| owner.is_none() && *pattern == quoted)
                {
                    self.count(&quoted, line);
                }
            }
            _ => {}
        }
        pos + 1
    }

    fn ident_at(&mut self, pos: usize, name: &str, line: usize) -> usize {
        let depth = self.stack.len();
        let previous = pos.checked_sub(1).and_then(|p| self.tok(p)).cloned();
        match name {
            "fn" => {
                if let Some(fn_name) = self.ident(pos + 1) {
                    self.pending = Some((Frame::Fn(fn_name.to_string()), depth));
                    return pos + 2;
                }
            }
            "trait" => {
                if let Some(trait_name) = self.ident(pos + 1) {
                    self.pending = Some((Frame::Impl(trait_name.to_string()), depth));
                    return pos + 2;
                }
            }
            "mod" => {
                if let Some(mod_name) = self.ident(pos + 1) {
                    self.pending = Some((Frame::Mod(mod_name.to_string()), depth));
                    return pos + 2;
                }
            }
            "impl" => {
                let item_position = match &previous {
                    None | Some(Tok::Punct(';' | '}' | '{' | ']')) => true,
                    Some(Tok::Ident(word)) => word == "unsafe" || word == "default",
                    _ => false,
                };
                if item_position {
                    let owner = self.impl_owner(pos + 1);
                    self.pending = Some((Frame::Impl(owner), depth));
                }
                return pos + 1;
            }
            _ => {}
        }
        if matches!(previous, Some(Tok::Ident(ref word)) if word == "fn") {
            return pos + 1;
        }
        if self.paths.is_some() {
            if name == "use" {
                return self.use_paths(pos);
            }
            return self.path_from(pos, previous.as_ref()).unwrap_or(pos + 1);
        }
        let wanted = self.counting;
        let owner = if matches!(previous, Some(Tok::Joint("::"))) {
            pos.checked_sub(2)
                .and_then(|at| self.ident(at))
                .map(str::to_string)
        } else {
            None
        };
        if let Some(label) = wanted_label(wanted, owner.as_deref(), name) {
            self.count(&label, line);
        }
        pos + 1
    }

    /// The paths of the `use` item at `pos`: each recorded if it leaves the
    /// node manager's code, and each that starts lower case (a module or a
    /// function) kept as an alias for the paths after it. Returns the
    /// position after the item.
    fn use_paths(&mut self, pos: usize) -> usize {
        let line = self.tokens.get(pos).map_or(0, |token| token.line);
        let mut start = pos + 1;
        if matches!(self.tok(start), Some(Tok::Joint("::"))) {
            start += 1;
        }
        let mut leaves = Vec::new();
        let mut end = self.use_tree(start, Vec::new(), &mut leaves);
        for (mut path, alias) in leaves {
            if path.last().is_some_and(|segment| segment == "self") {
                path.pop();
            }
            let name = alias.or_else(|| path.last().cloned());
            let Some(resolved) = self.resolve(&path) else {
                continue;
            };
            self.record_path(&resolved, line);
            if let (Some(name), Some(paths)) = (name, self.paths.as_mut()) {
                if name != "*" && name != "_" && !name.starts_with(char::is_uppercase) {
                    paths.aliases.insert(name, resolved);
                }
            }
        }
        while let Some(tok) = self.tok(end) {
            end += 1;
            if matches!(tok, Tok::Punct(';')) {
                break;
            }
        }
        end
    }

    /// The use tree at `pos`, below `prefix`: each leaf's path, with the
    /// name it is brought in as when renamed. Returns the position after it.
    fn use_tree(
        &self,
        mut pos: usize,
        prefix: Vec<String>,
        leaves: &mut Vec<(Vec<String>, Option<String>)>,
    ) -> usize {
        let mut path = prefix;
        loop {
            match self.tok(pos) {
                Some(Tok::Ident(segment)) => {
                    path.push(segment.clone());
                    pos += 1;
                }
                Some(Tok::Punct('*')) => {
                    path.push("*".to_string());
                    leaves.push((path, None));
                    return pos + 1;
                }
                Some(Tok::Punct('{')) => {
                    pos += 1;
                    loop {
                        match self.tok(pos) {
                            Some(Tok::Punct('}')) => return pos + 1,
                            Some(Tok::Punct(',')) => pos += 1,
                            None => return pos,
                            Some(_) => {
                                let next = self.use_tree(pos, path.clone(), leaves);
                                pos = next.max(pos + 1);
                            }
                        }
                    }
                }
                _ => return pos,
            }
            match self.tok(pos) {
                Some(Tok::Joint("::")) => pos += 1,
                Some(Tok::Ident(word)) if word == "as" => {
                    leaves.push((path, self.ident(pos + 1).map(str::to_string)));
                    return pos + 2;
                }
                _ => {
                    leaves.push((path, None));
                    return pos;
                }
            }
        }
    }

    /// A path from `pos` whose root can lead out of the node manager's code
    /// (`crate`, `self`, `super`, `ant_core`, or an alias a `use` made),
    /// recorded if it does. Returns the position after it, or `None` when
    /// no such path starts here (a later segment of a path, a method, a
    /// name of another crate's).
    fn path_from(&mut self, pos: usize, previous: Option<&Tok>) -> Option<usize> {
        if matches!(previous, Some(Tok::Joint("::") | Tok::Punct('.'))) {
            return None;
        }
        if !matches!(self.tok(pos + 1), Some(Tok::Joint("::"))) {
            return None;
        }
        let root = self.ident(pos)?.to_string();
        let known = matches!(root.as_str(), "crate" | "self" | "super" | "ant_core")
            || self
                .paths
                .as_ref()
                .is_some_and(|paths| paths.aliases.contains_key(&root));
        if !known {
            return None;
        }
        let mut segments = vec![root];
        let mut end = pos + 1;
        while matches!(self.tok(end), Some(Tok::Joint("::"))) {
            let Some(segment) = self.ident(end + 1) else {
                break;
            };
            segments.push(segment.to_string());
            end += 2;
        }
        let line = self.tokens.get(pos).map_or(0, |token| token.line);
        if let Some(resolved) = self.resolve(&segments) {
            self.record_path(&resolved, line);
        }
        Some(end)
    }

    /// `segments` from its crate's root: the crate and the path, or `None`
    /// for a path into another crate, or above its crate's root.
    fn resolve(&self, segments: &[String]) -> Option<(String, Vec<String>)> {
        let paths = self.paths.as_ref()?;
        let (root, rest) = segments.split_first()?;
        let mut module = paths.module.clone();
        module.extend(self.inline_modules());
        let (krate, mut path) = match root.as_str() {
            "crate" => (paths.krate.clone(), Vec::new()),
            "self" => (paths.krate.clone(), module),
            "super" => {
                let ups = segments.iter().take_while(|s| *s == "super").count();
                let kept = module.len().checked_sub(ups)?;
                module.truncate(kept);
                module.extend(segments[ups..].iter().cloned());
                return Some((paths.krate.clone(), module));
            }
            "ant_core" => ("ant_core".to_string(), Vec::new()),
            alias => paths.aliases.get(alias)?.clone(),
        };
        path.extend(rest.iter().cloned());
        Some((krate, path))
    }

    /// Count `resolved` in this file if it leaves the node manager's code,
    /// by its crate and its path up to and with its first type (a name that
    /// starts upper case), so a type's variants and associated items count
    /// as the type.
    fn record_path(&mut self, (krate, path): &(String, Vec<String>), line: usize) {
        if inside_node_manager(krate, path) {
            return;
        }
        let mut label = vec![krate.clone()];
        for segment in path {
            label.push(segment.clone());
            if segment.starts_with(char::is_uppercase) {
                break;
            }
        }
        self.scan
            .calls
            .entry(("<file>".to_string(), label.join("::")))
            .or_default()
            .push(line);
    }

    /// The type an `impl` header starting at `pos` names: after `for` if there
    /// is one, else the type itself, by the last path segment before its
    /// generic arguments.
    fn impl_owner(&self, mut pos: usize) -> String {
        let mut angle = 0usize;
        let mut segment: Option<String> = None;
        let mut owner: Option<String> = None;
        let mut closed_generics = false;
        while let Some(tok) = self.tok(pos) {
            match tok {
                Tok::Punct('{' | ';') => break,
                Tok::Ident(word) if angle == 0 && word == "where" => break,
                Tok::Ident(word) if angle == 0 && word == "for" => {
                    segment = None;
                    owner = None;
                    closed_generics = false;
                }
                Tok::Punct('<') => {
                    if angle == 0 && owner.is_none() {
                        owner = segment.clone();
                    }
                    angle += 1;
                }
                Tok::Punct('>') => {
                    angle = angle.saturating_sub(1);
                    if angle == 0 {
                        closed_generics = true;
                    }
                }
                Tok::Ident(word)
                    if angle == 0
                        && !matches!(word.as_str(), "dyn" | "mut" | "unsafe" | "const")
                        && (!closed_generics || owner.is_none()) =>
                {
                    segment = Some(word.clone());
                }
                _ => {}
            }
            pos += 1;
        }
        owner.or(segment).unwrap_or_else(|| "<impl>".to_string())
    }

    /// Handle an attribute starting with `#` at `pos`; skips what a test-only
    /// one is on. Returns where to continue.
    fn attribute(&mut self, pos: usize) -> usize {
        let inner = matches!(self.tok(pos + 1), Some(Tok::Punct('!')));
        let open = if inner { pos + 2 } else { pos + 1 };
        if !matches!(self.tok(open), Some(Tok::Punct('['))) {
            return pos + 1;
        }
        let close = matching_close(self.tokens, open);
        let attr = self.tokens.get(open + 1..close).unwrap_or(&[]);
        let test_only = is_test_only_attribute(attr);
        let after = close + 1;
        if !test_only {
            return after;
        }
        if inner {
            if self.stack.is_empty() {
                self.scan.test_only = true;
            }
            return self.end_of_frame(after);
        }
        self.skip_item(after)
    }

    /// The position of the bracket closing the current frame, from `pos`.
    fn end_of_frame(&self, mut pos: usize) -> usize {
        let mut depth = 0usize;
        while let Some(tok) = self.tok(pos) {
            match tok {
                Tok::Punct('(' | '[' | '{') => depth += 1,
                Tok::Punct(')' | ']' | '}') => {
                    if depth == 0 {
                        return pos;
                    }
                    depth -= 1;
                }
                _ => {}
            }
            pos += 1;
        }
        pos
    }

    /// Skip the item, statement, field or arm an outer test-only attribute is
    /// on, starting at `pos`. Errs towards skipping too little, never too much.
    fn skip_item(&mut self, mut pos: usize) -> usize {
        // Further attributes on the same item.
        while matches!(self.tok(pos), Some(Tok::Punct('#')))
            && matches!(self.tok(pos + 1), Some(Tok::Punct('[')))
        {
            pos = matching_close(self.tokens, pos + 1) + 1;
        }
        self.note_test_only_mod(pos);
        let mut depth = 0usize;
        let mut item_keyword = false;
        let mut brace_at_top = false;
        while let Some(tok) = self.tok(pos) {
            match tok {
                Tok::Ident(word) if depth == 0 && ITEM_KEYWORDS.contains(&word.as_str()) => {
                    item_keyword = true;
                }
                Tok::Punct(c @ ('(' | '[' | '{')) => {
                    if depth == 0 && *c == '{' {
                        brace_at_top = true;
                    }
                    depth += 1;
                }
                Tok::Punct(c @ (')' | ']' | '}')) => {
                    if depth == 0 {
                        return pos;
                    }
                    depth -= 1;
                    if depth == 0 && *c == '}' && brace_at_top {
                        return pos + 1;
                    }
                }
                Tok::Punct(';') if depth == 0 => return pos + 1,
                Tok::Punct(',') if depth == 0 && !item_keyword => return pos + 1,
                _ => {}
            }
            pos += 1;
        }
        pos
    }

    /// Record `[pub[(…)]] mod name;` at `pos` as a test-only declaration.
    fn note_test_only_mod(&mut self, mut pos: usize) {
        if self.ident(pos) == Some("pub") {
            pos += 1;
            if matches!(self.tok(pos), Some(Tok::Punct('('))) {
                pos = matching_close(self.tokens, pos) + 1;
            }
        }
        if self.ident(pos) != Some("mod") {
            return;
        }
        if let (Some(name), Some(Tok::Punct(';'))) = (self.ident(pos + 1), self.tok(pos + 2)) {
            let decl = ModDecl {
                within: self.inline_modules(),
                name: name.to_string(),
                test_only: true,
            };
            self.scan.decls.push(decl);
        }
    }
}

/// Scan one file's source for what `counting` counts.
fn scan_counting(source: &str, counting: Counting) -> FileScan {
    let tokens = tokenize(source);
    Walker::new(&tokens, counting).walk()
}

/// Scan one file of the node manager's code, at `place` (its crate and
/// module), for the paths that lead out of the node manager's code.
fn scan_paths(source: &str, (krate, module): (String, Vec<String>)) -> FileScan {
    let tokens = tokenize(source);
    let mut walker = Walker::new(&tokens, &[]);
    walker.paths = Some(PathScan {
        krate,
        module,
        aliases: BTreeMap::new(),
    });
    walker.walk()
}

/// Whether a path, from the root of `krate`, stays in the node manager's
/// code ([`NODE_MANAGER`]): ant-core's `node` module, the darwin binary's
/// `commands::node`, or anywhere in `darwin-nodes`, a crate of its own.
fn inside_node_manager(krate: &str, path: &[String]) -> bool {
    match krate {
        "ant_core" => path.first().is_some_and(|segment| segment == "node"),
        "darwin" => path.len() >= 2 && path[0] == "commands" && path[1] == "node",
        "darwin_nodes" => true,
        _ => false,
    }
}

/// The crate a file of the workspace belongs to and its module there, for
/// a file of the node manager's code (`ant-core/src/node/daemon/mod.rs` is
/// `ant_core`'s `node::daemon`); `None` for any other file.
fn node_manager_place(file: &str) -> Option<(String, Vec<String>)> {
    if !NODE_MANAGER.iter().any(|dir| file.starts_with(dir)) {
        return None;
    }
    let (krate, rest) = if let Some(rest) = file.strip_prefix("ant-core/src/") {
        ("ant_core", rest)
    } else if let Some(rest) = file.strip_prefix("ant-cli/src/bin/darwin-nodes/") {
        ("darwin_nodes", rest)
    } else {
        ("darwin", file.strip_prefix("ant-cli/src/")?)
    };
    let mut module: Vec<String> = rest
        .trim_end_matches(".rs")
        .split('/')
        .map(str::to_string)
        .collect();
    if matches!(rest, "main.rs" | "lib.rs") {
        module.clear();
    } else if module.last().is_some_and(|name| name == "mod") {
        module.pop();
    }
    Some((krate.to_string(), module))
}
// ---------------------------------------------------------------------------
// The crates
// ---------------------------------------------------------------------------

/// Every `.rs` file under `dir`, by path relative to `root` with `/`.
fn rust_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rust_files(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((relative, path));
        }
    }
}

/// The file a `mod` declaration in `file` refers to, if it is one of `files`.
fn declared_file(file: &str, decl: &ModDecl, files: &BTreeSet<String>) -> Option<String> {
    let (dir, name) = file.rsplit_once('/')?;
    let mut base = if matches!(name, "mod.rs" | "lib.rs" | "main.rs") {
        dir.to_string()
    } else {
        format!("{dir}/{}", name.trim_end_matches(".rs"))
    };
    for module in &decl.within {
        base = format!("{base}/{module}");
    }
    [
        format!("{base}/{}.rs", decl.name),
        format!("{base}/{}/mod.rs", decl.name),
    ]
    .into_iter()
    .find(|candidate| files.contains(candidate))
}

/// What `counting` mentions in the production code of the crate at `root`,
/// by `(file, site, name)`, with the lines they are on; files are named from
/// the workspace root (`ant-core/src/...`).
fn crate_census(
    crate_name: &str,
    root: &Path,
    counting: Counting,
) -> BTreeMap<(String, String, String), Vec<usize>> {
    crate_census_by(crate_name, root, &|_, source| {
        scan_counting(source, counting)
    })
}

/// [`crate_census`], with each file scanned by `scan`, given the file's name
/// from the workspace root and its source.
fn crate_census_by(
    crate_name: &str,
    root: &Path,
    scan: &dyn Fn(&str, &str) -> FileScan,
) -> BTreeMap<(String, String, String), Vec<usize>> {
    let mut files = Vec::new();
    rust_files(root, &root.join("src"), &mut files);
    let scans: BTreeMap<String, FileScan> = files
        .iter()
        .map(|(relative, path)| {
            let source = std::fs::read_to_string(path).unwrap_or_default();
            (
                relative.clone(),
                scan(&format!("{crate_name}/{relative}"), &source),
            )
        })
        .collect();
    let names: BTreeSet<String> = scans.keys().cloned().collect();

    // A file is test-only when every declaration of it is, or sits in a
    // test-only file.
    let mut declared_by: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    for (file, scan) in &scans {
        for decl in &scan.decls {
            if let Some(target) = declared_file(file, decl, &names) {
                declared_by
                    .entry(target)
                    .or_default()
                    .push((file.clone(), decl.test_only));
            }
        }
    }
    let mut test_only: BTreeSet<String> = scans
        .iter()
        .filter(|(_, scan)| scan.test_only)
        .map(|(file, _)| file.clone())
        .collect();
    loop {
        let newly: Vec<String> = declared_by
            .iter()
            .filter(|(target, _)| !test_only.contains(*target))
            .filter(|(_, decls)| {
                decls.iter().all(|(declarer, decl_test_only)| {
                    *decl_test_only || test_only.contains(declarer)
                })
            })
            .map(|(target, _)| target.clone())
            .collect();
        if newly.is_empty() {
            break;
        }
        test_only.extend(newly);
    }

    let mut found = BTreeMap::new();
    for (file, scan) in scans {
        if test_only.contains(&file) {
            continue;
        }
        for ((site, call), lines) in scan.calls {
            found.insert((format!("{crate_name}/{file}"), site, call), lines);
        }
    }
    found
}

/// Both crates' census of `counting`.
fn census(counting: Counting) -> BTreeMap<(String, String, String), Vec<usize>> {
    let cli = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = crate_census("ant-core", &cli.join("../ant-core"), counting);
    found.extend(crate_census("ant-cli", cli, counting));
    found
}

/// `reviewed` against what a census `found`: an empty string when they
/// agree, else each difference, unlisted mentions written as entries ready
/// to review.
fn differences(
    found: &BTreeMap<(String, String, String), Vec<usize>>,
    reviewed: &[Site],
) -> String {
    let mut listed: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut report = String::new();
    for (file, site, name, count, reason) in reviewed {
        let key = (
            (*file).to_string(),
            (*site).to_string(),
            (*name).to_string(),
        );
        if listed.insert(key, *count).is_some() {
            let _ = writeln!(report, "  listed twice: {file} {site} {name}");
        }
        if reason.trim().is_empty() {
            let _ = writeln!(report, "  listed without a reason: {file} {site} {name}");
        }
    }
    for (key, lines) in found {
        let allowed = listed.get(key).copied().unwrap_or(0);
        let (file, site, name) = key;
        if lines.len() != allowed {
            let at: Vec<String> = lines.iter().map(|line| format!("{file}:{line}")).collect();
            let _ = writeln!(
                report,
                "  found {}, listed {allowed} ({}):
    (\"{file}\", \"{site}\", {name:?}, {}, REASON),",
                lines.len(),
                at.join(", "),
                lines.len()
            );
        }
    }
    for ((file, site, name), allowed) in &listed {
        if !found.contains_key(&((*file).clone(), (*site).clone(), (*name).clone())) {
            let _ = writeln!(report, "  found 0, listed {allowed}: {file} {site} {name}");
        }
    }
    report
}

/// Fail with `rule` and the differences between both crates' census of
/// `counting` and `reviewed`, if there are any.
fn check(counting: Counting, reviewed: &[Site], rule: &str) {
    check_found(&census(counting), reviewed, rule);
}

/// The node manager's code: ant-core's `node` module, the darwin CLI's
/// `node` commands (off) and `darwin-nodes`, the storage-node image's
/// manager.
const NODE_MANAGER: &[&str] = &[
    "ant-core/src/node/",
    "ant-cli/src/commands/node/",
    "ant-cli/src/bin/darwin-nodes/",
];

/// [`check`], counting in the node manager's code only.
fn check_node_manager(counting: Counting, reviewed: &[Site], rule: &str) {
    let found = census(counting)
        .into_iter()
        .filter(|((file, _, _), _)| NODE_MANAGER.iter().any(|dir| file.starts_with(dir)))
        .collect();
    check_found(&found, reviewed, rule);
}

/// What the node manager's code ([`NODE_MANAGER`]) names outside its own
/// folders: every path from `crate`, `self`, `super`, `ant_core`, or a name a
/// `use` brought in, that resolves outside them, once a file, by crate and
/// path up to its first type. Test-only code is left out, as everywhere.
fn boundary_census() -> BTreeMap<(String, String, String), Vec<usize>> {
    let cli = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scan = |file: &str, source: &str| match node_manager_place(file) {
        Some(place) => scan_paths(source, place),
        None => scan_counting(source, &[]),
    };
    let mut found = crate_census_by("ant-core", &cli.join("../ant-core"), &scan);
    found.extend(crate_census_by("ant-cli", cli, &scan));
    found
        .into_iter()
        .map(|(key, mut lines)| {
            lines.truncate(1);
            (key, lines)
        })
        .collect()
}

/// Fail with `rule` and the differences between `found` and `reviewed`, if
/// there are any.
fn check_found(
    found: &BTreeMap<(String, String, String), Vec<usize>>,
    reviewed: &[Site],
    rule: &str,
) {
    let report = differences(found, reviewed);
    assert!(
        report.is_empty(),
        "
The sites in ant-core/src and ant-cli/src no longer match the reviewed list.

         {report}
{rule}

         To review a site: check it against that rule. Then add or change its entry in          ant-cli/tests/darwin_census.rs with the file, site and name exactly as shown, the          count, and a one-line reason naming how it goes through the rule, and have it          reviewed. For a listed site that has gone, remove or lower its entry.
"
    );
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
fn every_store_and_payment_is_reviewed() {
    check(
        STORES,
        STORE_SITES,
        "Every upload path of darwin's own commands and file shortcuts stores an envelope, \
         private by default with every payment field shown; raw paths are kept, documented as \
         carrying none; every payment is per chunk, in the network's token, with paid quotes \
         read back.",
    );
}

#[test]
fn every_visibility_and_payment_mode_choice_is_reviewed() {
    check(
        CHOICES,
        CHOICE_SITES,
        "Uploads are private by default with every payment field shown, and paid per chunk: \
         merkle (batch) payments are refused by the nodes, so no path may choose them.",
    );
}

#[test]
fn every_wallet_is_built_where_it_is_reviewed() {
    check(
        WALLETS,
        WALLET_SITES,
        "A wallet is built from the configured key and bound to the configured chain \
         (config::wallet), or funded on a local devnet; nowhere else.",
    );
}

#[test]
fn self_update_stays_off() {
    check(
        SELF_UPDATE,
        SELF_UPDATE_SITES,
        "Self-update is off in this build: `darwin update` refuses before it reaches any of \
         these.",
    );
}

#[test]
fn every_decode_is_reviewed() {
    check(
        DECODES,
        DECODE_SITES,
        "A data map read from the network is decoded only through decode_map_record, which \
         bounds it, or by the producer's root-map read, bounded by the chunks it decrypts; other \
         decodes read local files or other types.",
    );
}

#[test]
fn the_node_manager_deletes_no_node_data() {
    check_node_manager(
        ERASES,
        ERASE_SITES,
        "No path of the node manager deletes a node's data folder: the disk-pressure eviction is \
         gone, the storage-node image's manager (darwin-nodes) has no reset, and the darwin CLI's \
         `node reset` is off. What it deletes is its own process and port files, a node's pid \
         file, and download leftovers.",
    );
}

/// The erasure census above counts deletions written in the node manager's
/// folders only. This one lists the doors out of them: every path the
/// manager's code names in the rest of ant-core or the darwin binary (a
/// module, a function, a type), once a file. A call from the manager into
/// code that deletes, in `data/`, `update.rs` or a utility module, then
/// fails here until it is reviewed, with what it deletes.
///
/// Neither census covers other crates: what the manager calls in the
/// standard library or its dependencies, or ant-node's own pruning of a
/// node's data, which runs in the node and belongs to darwin-node's census.
/// Nor does it follow methods called on a value of a listed type, so a
/// listed type's reason says what its methods delete.
#[test]
fn the_node_manager_reaches_outside_its_code_only_where_reviewed() {
    check_found(
        &boundary_census(),
        BOUNDARY_SITES,
        "The node manager's code reaches the rest of ant-core and of the darwin binary only \
         through reviewed paths, none of which deletes a node's data folder: error types, the \
         platform's directories, a version check, a progress bar, and the devnet's client.",
    );
}

/// The boundary census resolves what a file names: `use` trees with groups,
/// renames and `self`, `super` chains from the file's module, aliases a
/// `use` made, and `crate::` and `ant_core::` paths written in full; and it
/// leaves out paths that stay in the manager's code, other crates' paths,
/// methods and test-only code.
#[test]
fn the_boundary_census_finds_every_path_out_of_the_node_manager() {
    let source = r#"
        use crate::{config, error::{Error, Result}};
        use crate::node::types::NodeConfig;
        use super::super::super::data::client::file as files;
        use super::health;
        use std::fs;

        pub(crate) fn serve(x: Thing) -> Result<()> {
            let _ = config::data_dir();
            files::delete_all();
            health::check();
            super::supervisor::run();
            self::helper();
            ant_core::update::replace_binary();
            let _ = crate::error::Error::NodeNotFound;
            x.self_check();
            fs::remove_file("x");
            Ok(())
        }

        #[cfg(test)]
        mod tests {
            use crate::data::Client;
        }
    "#;
    let scan = scan_paths(
        source,
        (
            "ant_core".to_string(),
            vec!["node".into(), "daemon".into(), "server".into()],
        ),
    );
    let found: Vec<&str> = scan.calls.keys().map(|(_, name)| name.as_str()).collect();
    assert_eq!(
        found,
        vec![
            "ant_core::config",
            "ant_core::config::data_dir",
            "ant_core::data::client::file",
            "ant_core::data::client::file::delete_all",
            "ant_core::error::Error",
            "ant_core::error::Result",
            "ant_core::update::replace_binary",
        ]
    );

    // The manager's files, by crate and module.
    assert_eq!(
        node_manager_place("ant-core/src/node/daemon/mod.rs"),
        Some(("ant_core".into(), vec!["node".into(), "daemon".into()]))
    );
    assert_eq!(
        node_manager_place("ant-cli/src/bin/darwin-nodes/main.rs"),
        Some(("darwin_nodes".into(), vec![]))
    );
    assert_eq!(
        node_manager_place("ant-cli/src/commands/node/add.rs"),
        Some((
            "darwin".into(),
            vec!["commands".into(), "node".into(), "add".into()]
        ))
    );
    assert_eq!(node_manager_place("ant-core/src/data/client/file.rs"), None);
}
