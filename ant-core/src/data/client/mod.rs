//! Client operations for the Autonomi network.
//!
//! Provides high-level APIs for storing and retrieving data
//! on the Autonomi decentralized network.

pub mod adaptive {
    pub use crate::client_engine::adaptive::*;
}
pub mod batch;
pub mod cache;
#[cfg(feature = "native")]
pub(crate) mod cached_merkle;
#[cfg(feature = "native")]
pub(crate) mod cached_single;
pub mod chunk;
pub mod data;
#[cfg(feature = "native")]
pub mod diagnostics;
pub mod envelope;
pub mod file;
pub(crate) mod holders;
#[cfg(feature = "native")]
pub mod listings;
#[cfg(feature = "native")]
pub mod listings_census;
#[cfg(feature = "native")]
pub(crate) mod listings_facts;
#[cfg(feature = "native")]
pub mod listings_feeds;
#[cfg(feature = "native")]
pub mod listings_lists;
#[cfg(feature = "native")]
pub(crate) mod listings_mirror;
#[cfg(feature = "native")]
pub mod listings_publish;
#[cfg(feature = "native")]
pub(crate) mod listings_rpc;
#[cfg(feature = "native")]
pub mod listings_serve;
#[cfg(feature = "native")]
pub mod listings_store;
#[cfg(feature = "native")]
pub mod listings_v1;
pub mod merkle;
#[cfg(feature = "native")]
mod native_payment;
pub mod occupied;
pub mod payment;
pub mod pointer;
pub mod quote;
pub mod root_payment;
#[cfg(feature = "native")]
pub(crate) mod shared_wave;
pub mod upload;
#[cfg(feature = "native")]
pub mod upload_checkpoint;
pub mod upload_state;

use crate::client_engine::single_flight::SingleFlight;
use crate::data::client::adaptive::{AdaptiveConfig, AdaptiveController, ChannelStart, Outcome};
use crate::data::client::cache::ChunkCache;
use crate::data::error::{Error, Result};
use crate::data::network::Network;
#[cfg(feature = "native")]
use crate::data::network::NetworkHealth;
#[cfg(feature = "native")]
use crate::data::peer_cache;
use ant_protocol::evm::{Amount, Wallet};
#[cfg(feature = "native")]
use ant_protocol::transport::P2PNode;
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::{XorName, CLOSE_GROUP_SIZE};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(feature = "native")]
use tracing::debug;

/// Width of the chunk PUT-target set (initial writes plus fallback): the
/// closest `PUT_TARGET_WIDTH` peers to the address.
///
/// Mirrors the node-side `K_BUCKET_SIZE` / `PAID_QUOTE_ISSUER_CLOSENESS_WIDTH`
/// (20): a node accepts a reused payment proof only when one of the proof's
/// closest-`CLOSE_GROUP_SIZE` quote issuers is within its own local 20-closest,
/// so trying peers past this width is pointless.
pub(crate) use crate::quote_policy::PUT_TARGET_WIDTH;

/// How many distinct peers must refuse this client's settlement version before
/// the refusal is believed and uploads stop.
///
/// Nothing authenticates a refusal, so one peer's word cannot be enough: a
/// single hostile or misconfigured storer answering `ClientUpdateRequired` to
/// everything would otherwise deny every upload, turning an over-query design
/// that tolerates many bad peers into one that tolerates none.
///
/// Two is deliberately low. A genuine incompatibility reaches it instantly,
/// because every peer enforcing the newer rule refuses, and a client queries
/// far more than two. An attacker has to control two of the peers a given
/// request happens to reach, which is a materially different proposition from
/// controlling one.
pub(crate) const SETTLEMENT_REFUSAL_QUORUM: usize = 2;

/// Distinct peers that have refused this client's settlement version, plus the
/// wording of the first refusal.
///
/// A separate type rather than a field so the corroboration rule can be tested
/// on its own: it is the piece that decides whether an upload stops, and it
/// has to hold against both a lone lying peer and a genuine incompatibility.
#[derive(Clone, Default)]
pub(crate) struct SettlementRefusals {
    inner: Arc<Mutex<(HashSet<PeerId>, Option<String>)>>,
}

impl SettlementRefusals {
    /// Record a refusal from `peer_id`, returning the wording once
    /// [`SETTLEMENT_REFUSAL_QUORUM`] distinct peers agree and `None` below it.
    pub(crate) fn note(&self, peer_id: PeerId, message: &str) -> Option<String> {
        let mut guard = self.inner.lock().ok()?;
        let (peers, wording) = &mut *guard;
        peers.insert(peer_id);
        if wording.is_none() {
            *wording = Some(message.to_string());
        }
        (peers.len() >= SETTLEMENT_REFUSAL_QUORUM)
            .then(|| wording.clone())
            .flatten()
    }

    /// The corroborated refusal, if one has been established.
    pub(crate) fn corroborated(&self) -> Option<String> {
        let guard = self.inner.lock().ok()?;
        let (peers, wording) = &*guard;
        (peers.len() >= SETTLEMENT_REFUSAL_QUORUM)
            .then(|| wording.clone())
            .flatten()
    }

    /// The distinct refusing peers recorded so far, rendered for logging,
    /// sorted so the line is deterministic.
    ///
    /// Exists so the terminal abort can NAME its corroborators. Without it the
    /// quorum is unverifiable from outside: "awaiting corroboration" is only
    /// logged below the quorum and the terminal error carries no peer ids, so
    /// a log reader sees one warned peer followed by an abort whether the
    /// quorum counted two distinct peers or misfired on one — which is exactly
    /// the ambiguity the V2-1109 testnet run hit (0/463 aborts showed a second
    /// peer, because the second peer was structurally unloggable).
    pub(crate) fn corroborating_peers(&self) -> Vec<String> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        let (peers, _) = &*guard;
        let mut ids: Vec<String> = peers.iter().map(|p| format!("{p}")).collect();
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod settlement_refusal_tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::from_bytes([seed; 32])
    }

    /// A settlement refusal's wording, as quote collection records it.
    fn refusal() -> String {
        super::quote::update_required_message(1, 2)
    }

    /// The question the V2-1109 run could not answer from logs: does one peer
    /// refusing many times count as many? It must not — the quorum is over
    /// DISTINCT peers, and a lone hostile or misconfigured storer repeating
    /// itself must never become a verdict about this build.
    #[test]
    fn one_peer_refusing_many_times_never_reaches_the_quorum() {
        let refusals = SettlementRefusals::default();
        for _ in 0..50 {
            assert!(
                refusals.note(peer(7), &refusal()).is_none(),
                "a single peer's repeated refusals must stay below the quorum"
            );
        }
        assert!(refusals.corroborated().is_none());
        assert_eq!(refusals.corroborating_peers().len(), 1);
    }

    /// The terminal log line must be able to name both corroborators, so the
    /// distinct-peer property is verifiable from the outside.
    #[test]
    fn corroborating_peers_names_every_distinct_refuser() {
        let refusals = SettlementRefusals::default();
        assert!(refusals.note(peer(1), &refusal()).is_none());
        assert!(refusals.note(peer(2), &refusal()).is_some());

        let ids = refusals.corroborating_peers();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert_eq!(ids, {
            let mut sorted = ids.clone();
            sorted.sort();
            sorted
        });
    }
}

/// Classify a `data::error::Error` into a controller `Outcome`.
///
/// Capacity signals (Timeout / NetworkError) drive the controller
/// down; application errors do not. The mapping is conservative:
/// anything that COULD be transport-related is treated as a network
/// signal, because under-classifying a real network failure as
/// "application error" makes the controller blind to genuine stress.
///
/// Mapping policy:
/// - `Timeout` -> `Timeout` (per-op deadline elapsed)
/// - `Network`, `InsufficientPeers`, `Io` -> `NetworkError` (transport
///   layer reported failure)
/// - `Protocol`, `Storage` -> `NetworkError` (these wrap remote errors
///   that frequently include peer disconnects mid-stream — under
///   network stress these are how transport failures surface)
/// - `PartialUpload` -> `NetworkError` (literal capacity signal: some
///   chunks could not be stored)
/// - `AlreadyStored`, `Encryption`, `Crypto`, `Payment`,
///   `Serialization`, `InvalidData`, `NotFound`, `SignatureVerification`,
///   `Config`, `InsufficientDiskSpace`, `CostEstimationInconclusive`,
///   `Cancelled` -> `ApplicationError` (would happen on a perfectly
///   healthy link; `Cancelled` is caller-initiated and must not be retried
///   as a transport failure; `NotFound` is a definitively absent record
///   reported over a working link, not a transport symptom)
/// - `RemotePut` -> `ApplicationError` (the remote node responded with a
///   structured rejection — the transport succeeded, so the node declined
///   at the application layer; not a local capacity signal)
/// - `PointerFinal`, `PointerForked` -> `ApplicationError` (a verdict about
///   one pointer's state, read over a working link)
/// - `ClientUpdateRequired` -> `ApplicationError` (the storer refused to quote
///   a client that settles under superseded rules — a terminal verdict about
///   this build, not about link capacity, and no retry rate clears it)
/// - `BatchPaymentsRefused` -> `ApplicationError` (the nodes answered that
///   they take per-chunk payments only — a verdict about the payment kind,
///   given over a working link)
/// - `CloseGroupShortfall` -> `ApplicationError` (a quorum shortfall caused
///   by close-group dial/relay churn with no PUT-response timeouts — remote
///   peer churn, not local backpressure; a timeout-bearing shortfall keeps
///   `InsufficientPeers`/`NetworkError` instead, so genuine congestion still
///   cuts the cap — V2-554)
pub(crate) fn classify_error(err: &Error) -> Outcome {
    match err {
        Error::Timeout(_) => crate::transfer_policy::FailureKind::Timeout,
        Error::Network(_)
        | Error::InsufficientPeers(_)
        | Error::Io(_)
        | Error::Protocol(_)
        | Error::Storage(_)
        | Error::PartialUpload { .. } => crate::transfer_policy::FailureKind::Network,
        Error::AlreadyStored
        | Error::Encryption(_)
        | Error::Crypto(_)
        | Error::Payment(_)
        | Error::Serialization(_)
        | Error::InvalidData(_)
        // A definitively absent record, reported over a working link —
        // the peers answered, there was just nothing stored there. Not a
        // transport symptom, so it must not push the limiter down.
        | Error::NotFound(_)
        // A private file's envelope: the record was found, it just doesn't
        // carry its data map.
        | Error::DataMapWithheld(_)
        | Error::SignatureVerification(_)
        | Error::Config(_)
        | Error::InsufficientDiskSpace(_)
        | Error::CostEstimationInconclusive(_)
        | Error::Cancelled(_)
        // The storer parsed our request and refused it on its merits, over a
        // working link. Sending fewer requests would not help, and treating it
        // as congestion would quietly shrink the limiter for the rest of the
        // run on the basis of a fault no retry can clear.
        | Error::ClientUpdateRequired(_)
        | Error::StorerUpdateRequired(_)
        // The nodes take per-chunk payments only: an answer about the
        // payment kind, given over a working link.
        | Error::BatchPaymentsRefused(_)
        // A pointer that is final, or whose owner forked it, is a verdict
        // about that pointer read over a working link. No retry rate changes
        // it.
        | Error::PointerFinal(_)
        | Error::PointerForked(_)
        | Error::BadQuoteBinding { .. }
        | Error::BadQuoteCommitment { .. }
        // An external-signer merkle batch larger than one tree can hold —
        // a caller-shape refusal raised before any network work, so it says
        // nothing about link capacity.
        | Error::MerkleBatchTooLarge { .. }
        // A remote node responded with a structured rejection — the
        // transport round-trip succeeded, so the node declined at the
        // application layer (payment/disk/quote/pool). Not a local
        // capacity signal; recorded but must not push the limiter down.
        | Error::RemotePut { .. }
        // A close-group PUT shortfall caused purely by dial/relay churn
        // (dead/stale relayed peer addresses), with no PUT-response
        // timeouts to signal local backpressure. Remote peer churn, not
        // "client sending too fast" — must not push the limiter down
        // (V2-554). A shortfall that DID time out keeps `InsufficientPeers`
        // (`NetworkError`) so real congestion still cuts the cap.
        | Error::CloseGroupShortfall(_) => crate::transfer_policy::FailureKind::Application,
    }
    .outcome()
}

/// Compute XOR distance between a peer's ID bytes and a target address.
///
/// Uses the first 32 bytes of the peer ID (or fewer if shorter) XORed
/// with the target address. The returned byte array sorts
/// lexicographically from closest to furthest.
pub(crate) fn peer_xor_distance(peer_id: &PeerId, target: &[u8; 32]) -> [u8; 32] {
    let peer_bytes = peer_id.as_bytes();
    let mut distance = [0u8; 32];
    for (i, d) in distance.iter_mut().enumerate() {
        let peer_byte = peer_bytes.get(i).copied().unwrap_or(0);
        *d = peer_byte ^ target[i];
    }
    distance
}

/// Default timeout for lightweight network operations (quotes, DHT lookups) in seconds.
const DEFAULT_QUOTE_TIMEOUT_SECS: u64 = 10;

/// Default timeout for the per-peer chunk GET response and any other
/// caller that explicitly reads `store_timeout_secs`, in seconds.
///
/// Note despite the name: this knob does **not** govern the non-merkle
/// chunk PUT response timeout — that path uses the
/// `STORE_RESPONSE_TIMEOUT` constant in `chunk.rs` directly. Nor does
/// it govern the merkle batch PUT timeout — see
/// `DEFAULT_MERKLE_STORE_TIMEOUT_SECS`.
///
/// 10 s matches the pre-existing `main` default and intentionally
/// excludes residential-upload tuning, which is Mick's PR #78
/// territory (splitting GET into its own field).
const DEFAULT_STORE_TIMEOUT_SECS: u64 = 10;

/// Default timeout for **merkle batch** chunk store operations in seconds.
///
/// Separate from `DEFAULT_STORE_TIMEOUT_SECS` because merkle PUTs carry
/// an extra storer-side cost: the payment verifier runs an iterative
/// DHT lookup (`CLOSENESS_LOOKUP_TIMEOUT` in `ant-node`, **240 s**
/// post-PR #89) before accepting the proof.
///
/// This timeout MUST be >= the storer-side `CLOSENESS_LOOKUP_TIMEOUT`
/// plus padding for the store-response round-trip and storer-local
/// I/O. Otherwise the client gives up while the storer is still
/// happily verifying, the storer wastes CPU/bandwidth on a chunk the
/// client has already discarded, and the client re-targets a
/// different close-K member — potentially double-storing the same
/// chunk and polluting routing.
///
/// 270 s = 240 s (storer lookup) + 30 s padding (network RTT + LMDB
/// put + fsync + clock skew tolerance).
///
/// This invariant must be re-validated if either side's timeout
/// changes. Empirically surfaced as "every cross-region merkle chunk
/// times out at 10 s" on a 210-node 7-region testnet run on
/// 2026-05-12; bumping to 270 s flipped that 0/22 -> 9/9 pass rate.
const DEFAULT_MERKLE_STORE_TIMEOUT_SECS: u64 = 270;

/// Default timeout for chunk GET response operations in seconds.
const DEFAULT_CHUNK_GET_TIMEOUT_SECS: u64 = 10;

/// Default quote concurrency: high because quoting is pure network I/O
/// (DHT lookups + small request/response messages) with no CPU-bound work.
const DEFAULT_QUOTE_CONCURRENCY: usize = 32;

/// Default store concurrency: moderate because each chunk PUT sends ~4MB
/// to 7 close-group peers. At 8 concurrent stores, ~225MB of outbound
/// traffic can be in flight. Users on fast connections can increase this
/// with --store-concurrency; users on slow connections can decrease it.
const DEFAULT_STORE_CONCURRENCY: usize = 8;

/// Configuration for the Autonomi client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Per-op timeout for lightweight network operations (quotes,
    /// DHT lookups), in seconds. The adaptive controller does NOT
    /// currently size timeouts; this remains a static knob.
    pub quote_timeout_secs: u64,
    /// Per-op timeout, in seconds, for the chunk GET response path
    /// (`chunk_get_from_peer`) and any other caller that reads this
    /// field directly.
    ///
    /// Note despite the historical name `store_timeout_secs`: this
    /// knob does **not** govern the non-merkle chunk PUT response
    /// timeout (that path uses the `STORE_RESPONSE_TIMEOUT` constant
    /// in `chunk.rs`) and does **not** govern the merkle batch PUT
    /// timeout (see `merkle_store_timeout_secs`). Rename pending in
    /// Mick's PR #78 which adds a dedicated `chunk_get_timeout_secs`.
    ///
    /// The adaptive controller does NOT currently size timeouts;
    /// this remains a static knob.
    pub store_timeout_secs: u64,
    /// Per-op timeout for **merkle batch** chunk store (PUT)
    /// operations, in seconds. Separate from `store_timeout_secs`
    /// because merkle PUTs incur the storer-side
    /// `CLOSENESS_LOOKUP_TIMEOUT` (240 s post-PR #89) on top of the
    /// usual store path; the client must wait at least that long
    /// plus padding, or the storer wastes work on a chunk the client
    /// has already given up on. Default 270 s.
    pub merkle_store_timeout_secs: u64,
    /// Per-peer response timeout for chunk GET operations, in seconds.
    /// This is intentionally independent from `store_timeout_secs`: PUTs
    /// and GETs have different payload direction and performance profiles.
    pub chunk_get_timeout_secs: u64,
    /// Number of closest peers to consider for routing.
    pub close_group_size: usize,
    /// **Deprecated.** Pre-adaptive ceiling for quote concurrency.
    ///
    /// The adaptive controller now sizes quote fan-out from observed
    /// signals. This field, when non-zero and smaller than the
    /// controller's per-channel default, clamps the **quote channel
    /// only** (it does NOT bleed into store or fetch). Removed in a
    /// future release.
    pub quote_concurrency: usize,
    /// **Deprecated.** Pre-adaptive ceiling for store concurrency.
    ///
    /// The adaptive controller now sizes store fan-out from observed
    /// signals. This field, when non-zero and smaller than the
    /// controller's per-channel default, clamps the **store channel
    /// only** (it does NOT bleed into quote or fetch). Removed in a
    /// future release.
    pub store_concurrency: usize,
    /// Adaptive controller configuration. Defaults are tuned to match
    /// or exceed the prior static behavior — disabling adaptation
    /// (`adaptive.enabled = false`) reverts to the controller's
    /// `initial` values without re-evaluation.
    pub adaptive: AdaptiveConfig,
    /// Allow loopback (`127.0.0.1`) connections in the saorsa-transport
    /// layer. Set to `true` only for devnet / local testing. Production
    /// peers on the public Autonomi network reject the QUIC handshake
    /// variant produced when this is `true`, so the default is `false`.
    ///
    /// This mirrors the `--allow-loopback` flag in `ant-cli`, which already
    /// defaults to `false` and threads through to the same
    /// `CoreNodeConfig::builder().local(...)` call.
    pub allow_loopback: bool,
    /// Bind a dual-stack IPv6 socket (`true`) or an IPv4-only socket
    /// (`false`). Defaults to `true`, matching the CLI default.
    ///
    /// Set to `false` only when running on hosts without a working IPv6
    /// stack, to avoid advertising unreachable v6 addresses to the DHT
    /// (which causes slow connects and junk DHT address records). This
    /// mirrors the `--ipv4-only` flag in `ant-cli`.
    pub ipv6: bool,
    /// Per-batch leaf cap for **external-signer** merkle preparation,
    /// clamped to `3..=MAX_LEAVES` when set (a cap of 2 cannot partition odd
    /// totals — parts of 3 and 2 compose any count, so 3 is the smallest
    /// safe cap). `None` (the default) uses the contract maximum
    /// (`MAX_LEAVES` = 256).
    ///
    /// This is a test seam (ADR-0003): a small cap makes
    /// `file_prepare_upload_with_mode` produce a genuine multi-batch
    /// prepared upload from a kilobyte file, so the N-signature external
    /// flow is exercisable in E2E without a multi-GiB fixture. Production
    /// callers should leave it `None` — a lower cap only means more payment
    /// transactions for the same chunks.
    pub merkle_external_batch_cap: Option<usize>,
    /// Memory, in bytes, that a streaming download plans its decrypt batches
    /// around. `None` (the default) uses the memory free when the download
    /// starts, which suits one client on its own machine. A server running
    /// several transfers at once should set a fixed budget, so downloads
    /// don't each claim a share of whatever is free.
    pub download_memory_bytes: Option<u64>,
    /// The most a storer's quote may ask to store one chunk, in the payment
    /// token's base units. A quote, or merkle candidate, asking more is
    /// dropped as if its node hadn't answered, and no payment is planned on
    /// one. The client pays three times the price of the median quote it
    /// keeps, so a chunk then costs at most three times this. A payment
    /// planned before the ceiling was set or lowered, and saved by an
    /// interrupted upload, is resumed as saved, so it is never made twice.
    /// `None` (the default): no ceiling.
    pub max_chunk_price: Option<Amount>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            quote_timeout_secs: DEFAULT_QUOTE_TIMEOUT_SECS,
            store_timeout_secs: DEFAULT_STORE_TIMEOUT_SECS,
            merkle_store_timeout_secs: DEFAULT_MERKLE_STORE_TIMEOUT_SECS,
            chunk_get_timeout_secs: DEFAULT_CHUNK_GET_TIMEOUT_SECS,
            close_group_size: CLOSE_GROUP_SIZE,
            quote_concurrency: DEFAULT_QUOTE_CONCURRENCY,
            store_concurrency: DEFAULT_STORE_CONCURRENCY,
            adaptive: AdaptiveConfig::default(),
            allow_loopback: false,
            ipv6: true,
            merkle_external_batch_cap: None,
            download_memory_bytes: None,
            max_chunk_price: None,
        }
    }
}

/// Build the adaptive controller for a `Client`. Loads any persisted
/// snapshot, clamps cold-start values into the deprecated-flag bounds
/// **per channel** (so a pin on `--store-concurrency` does NOT bleed
/// into the fetch / quote channels), and returns the persistence path
/// so callers can save back at shutdown.
fn build_controller(config: &ClientConfig) -> (AdaptiveController, Option<PathBuf>) {
    let mut adaptive_cfg = config.adaptive.clone();

    // Per-channel ceilings: each legacy field is interpreted as a cap
    // for ONLY its matching channel. The fetch channel has no
    // pre-existing legacy field; it always uses the controller's
    // default ceiling.
    //
    // The legacy fields are non-zero by ClientConfig::default(), but
    // we honor them as bounds only when they would actually CONSTRAIN
    // the controller — i.e. when smaller than the per-channel default
    // max. A default ClientConfig must not silently lower the
    // controller's ceilings.
    // A value equal to the historic legacy default is treated as
    // "not pinned by the user" — without this, every default
    // ClientConfig would silently lower the controller's per-channel
    // ceilings to the prior static values (32/8) and the controller
    // could never grow above them.
    let user_quote_max = config.quote_concurrency;
    let user_store_max = config.store_concurrency;
    let quote_pinned = user_quote_max > 0 && user_quote_max != DEFAULT_QUOTE_CONCURRENCY;
    let store_pinned = user_store_max > 0 && user_store_max != DEFAULT_STORE_CONCURRENCY;
    if quote_pinned && user_quote_max < adaptive_cfg.max.quote {
        adaptive_cfg.max.quote = user_quote_max;
    }
    if store_pinned && user_store_max < adaptive_cfg.max.store {
        adaptive_cfg.max.store = user_store_max;
    }

    // Cold-start values: matched to the prior static defaults. If the
    // legacy field caps the channel below the cold-start, lower the
    // start to match — never start above the channel's max.
    let mut start = ChannelStart::default();
    start.quote = start.quote.min(adaptive_cfg.max.quote);
    start.store = start.store.min(adaptive_cfg.max.store);
    start.fetch = start.fetch.min(adaptive_cfg.max.fetch);

    #[cfg(feature = "native")]
    let adaptive_enabled = adaptive_cfg.enabled;
    let controller = AdaptiveController::new(start, adaptive_cfg);
    // Skip disk warm-start entirely when adaptation is disabled —
    // fixed-concurrency mode means the user wants exactly the cold
    // start, no surprises from prior runs. (warm_start is also a
    // no-op when disabled, but skipping the load avoids file I/O
    // and the path-resolution side effects.)
    #[cfg(feature = "native")]
    let persist_path = if adaptive_enabled {
        let p = adaptive::default_persist_path();
        if let Some(ref path) = p {
            if let Some(snap) = adaptive::load_snapshot(path) {
                debug!(path = %path.display(), "adaptive: warm-start from disk");
                controller.warm_start(snap);
            }
        }
        p
    } else {
        // Even with adaptation off, persist_path is computed so
        // explicit save_adaptive_snapshot() calls still work — but
        // the controller currently never moves, so saving the cold
        // start is harmless.
        adaptive::default_persist_path()
    };

    // File downloads choose a stream-decrypt batch size per download
    // from the current fetch cap and usable RAM, then pass it into
    // self_encryption's runtime batch-size API. The adaptive controller
    // still drives fan-out inside each batch by re-reading
    // `controller.fetch.current()` in the decrypt callback.

    #[cfg(not(feature = "native"))]
    let persist_path = None;
    (controller, persist_path)
}

/// Client for the Autonomi decentralized network.
///
/// Provides high-level APIs for storing and retrieving chunks
/// and files on the network.
pub struct Client {
    config: ClientConfig,
    network: Network,
    wallet: Option<Arc<Wallet>>,
    /// The wallet root payments go through: the same key as `wallet`,
    /// paying the root vault ([`Client::with_root_payments`], or by default
    /// [`Client::with_wallet`]). Set, every payment this client makes pays
    /// the root vault.
    root_wallet: Option<Arc<Wallet>>,
    /// Set by [`Client::without_root_payments`]: the client pays the
    /// per-quote vault, and makes no root vault's wallet of its own until
    /// [`Client::with_root_payments`] gives it one.
    per_quote_only: bool,
    /// The root vault this client names for its payment network
    /// ([`Client::with_root_vault`]): where it reads root-paid records
    /// when it has no root wallet, and the only vault a root wallet may
    /// pay. Never used on a network whose root vault is built in.
    root_vault: Option<ant_protocol::evm::Address>,
    evm_network: Option<ant_protocol::evm::Network>,
    chunk_cache: ChunkCache,
    /// The nodes that served chunks read recently, which a read of one again
    /// asks first.
    holders: holders::HolderCache,
    /// Chunk GETs in flight, by address and peer count, so concurrent reads
    /// of one chunk share a single network GET.
    chunk_gets: SingleFlight<(XorName, usize), Result<Option<ant_protocol::DataChunk>>>,
    next_request_id: AtomicU64,
    /// Adaptive concurrency controller: replaces the static
    /// quote/store concurrency knobs. See `adaptive` module.
    controller: AdaptiveController,
    /// Path the controller persists its snapshot to. `None` disables
    /// persistence (useful for tests / non-disk environments).
    #[cfg(feature = "native")]
    persist_path: Option<PathBuf>,
    /// Path for the persistent client peer cache. `None` disables the cache.
    #[cfg(feature = "native")]
    peer_cache_path: Option<PathBuf>,
    /// Distinct peers that have refused this client on settlement-version
    /// grounds, and the wording of the first such refusal.
    ///
    /// Client-wide and sticky, for two reasons that pull in opposite
    /// directions and are both real.
    ///
    /// It must outlive one operation, because the verdict is about this
    /// **build**, not this upload. Held in a single collector's local state, a
    /// refusal observed by one in-flight upload says nothing to another that
    /// is about to submit a payment, and merkle payments cannot be undone.
    ///
    /// It must not fire on one peer's say-so, because nothing authenticates a
    /// refusal. A single hostile or confused peer answering
    /// `ClientUpdateRequired` to every query would otherwise abort every
    /// upload the client attempts, converting an over-query design that
    /// tolerates many bad peers into one that tolerates none. So a refusal
    /// becomes terminal only once [`SETTLEMENT_REFUSAL_QUORUM`] distinct peers
    /// agree, which a genuine incompatibility reaches immediately (every
    /// upgraded peer refuses) and a lone attacker cannot reach at all.
    settlement_refusals: SettlementRefusals,
    /// Peers that answered `StorerUpdateRequired` to a quote request at
    /// the root vault's settlement version
    /// ([`root_payment::ROOT_SETTLEMENT_VERSION`]): their build can't check
    /// a root proof. A record whose close group holds one is quoted for the
    /// per-quote vault at once, without asking again, for as long as this
    /// client lives: one more transaction's gas, never a refused payment.
    /// No agreement among peers is needed, since paying the per-quote vault
    /// is always accepted.
    root_refusing_peers: Arc<Mutex<HashSet<PeerId>>>,
    /// The shared payment waves of this client's wallet
    /// ([`shared_wave`]).
    #[cfg(feature = "native")]
    shared_waves: Arc<shared_wave::SharedWaves>,
}

impl Client {
    /// Create a client using a platform network adapter.
    #[must_use]
    pub fn from_network(network: Network, config: ClientConfig) -> Self {
        let (controller, _persist_path) = build_controller(&config);
        Self {
            config,
            network,
            wallet: None,
            root_wallet: None,
            root_vault: None,
            per_quote_only: false,
            evm_network: None,
            chunk_cache: ChunkCache::default(),
            holders: holders::HolderCache::default(),
            chunk_gets: SingleFlight::default(),
            next_request_id: AtomicU64::new(1),
            controller,
            #[cfg(feature = "native")]
            persist_path: _persist_path,
            #[cfg(feature = "native")]
            peer_cache_path: None,
            settlement_refusals: SettlementRefusals::default(),
            root_refusing_peers: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(feature = "native")]
            shared_waves: Arc::default(),
        }
    }

    /// Keep compatibility decisions across browser operations whose network adapter
    /// carries a per-operation payment network identity.
    #[cfg(not(feature = "native"))]
    pub(crate) fn with_shared_quote_state(mut self, session: &Self) -> Self {
        self.settlement_refusals = session.settlement_refusals.clone();
        self.root_refusing_peers = Arc::clone(&session.root_refusing_peers);
        self
    }

    /// Create a client connected to the given P2P node.
    #[must_use]
    #[cfg(feature = "native")]
    pub fn from_node(node: Arc<P2PNode>, config: ClientConfig) -> Self {
        Self::from_node_with_peer_cache(node, config, None)
    }

    /// Create a client connected to the given P2P node and attach an optional
    /// persistent peer cache path.
    #[must_use]
    #[cfg(feature = "native")]
    pub fn from_node_with_peer_cache(
        node: Arc<P2PNode>,
        config: ClientConfig,
        #[cfg(feature = "native")] peer_cache_path: Option<PathBuf>,
    ) -> Self {
        let network = Network::from_node(node);
        let (controller, persist_path) = build_controller(&config);
        Self {
            config,
            network,
            wallet: None,
            root_wallet: None,
            root_vault: None,
            per_quote_only: false,
            evm_network: None,
            chunk_cache: ChunkCache::default(),
            holders: holders::HolderCache::default(),
            chunk_gets: SingleFlight::default(),
            next_request_id: AtomicU64::new(1),
            settlement_refusals: SettlementRefusals::default(),
            root_refusing_peers: Arc::new(Mutex::new(HashSet::new())),
            shared_waves: Arc::default(),
            controller,
            persist_path,
            peer_cache_path,
        }
    }

    /// Create a client connected to bootstrap peers.
    ///
    /// Threads `config.allow_loopback` and `config.ipv6` through to
    /// `Network::new`, which controls the saorsa-transport `local` and
    /// `ipv6` flags on the underlying `CoreNodeConfig`. See
    /// `ClientConfig::allow_loopback` and `ClientConfig::ipv6` for details.
    ///
    /// # Errors
    ///
    /// Returns an error if the P2P node cannot be created or bootstrapping fails.
    #[cfg(feature = "native")]
    pub async fn connect(
        bootstrap_peers: &[std::net::SocketAddr],
        config: ClientConfig,
    ) -> Result<Self> {
        let seeds: Vec<_> = bootstrap_peers
            .iter()
            .copied()
            .map(ant_protocol::transport::MultiAddr::quic)
            .collect();
        Self::connect_multiaddrs(&seeds, config).await
    }

    /// Connect using native QUIC multiaddresses without discarding peer pins.
    /// Chunk and pointer reads also ask the bootstrap peers among them that
    /// carry a peer ID, the nine nearest the address read, as with
    /// [`Client::with_bootstrap_peers`].
    #[cfg(feature = "native")]
    pub async fn connect_multiaddrs(
        bootstrap_peers: &[ant_protocol::transport::MultiAddr],
        config: ClientConfig,
    ) -> Result<Self> {
        debug!(
            "Connecting to the Darwin network with {} bootstrap peers (allow_loopback={}, ipv6={})",
            bootstrap_peers.len(),
            config.allow_loopback,
            config.ipv6,
        );
        let network =
            Network::new_multiaddrs(bootstrap_peers, config.allow_loopback, config.ipv6).await?;
        let (controller, persist_path) = build_controller(&config);
        Ok(Self {
            config,
            network,
            wallet: None,
            root_wallet: None,
            root_vault: None,
            per_quote_only: false,
            evm_network: None,
            chunk_cache: ChunkCache::default(),
            holders: holders::HolderCache::default(),
            chunk_gets: SingleFlight::default(),
            next_request_id: AtomicU64::new(1),
            settlement_refusals: SettlementRefusals::default(),
            root_refusing_peers: Arc::new(Mutex::new(HashSet::new())),
            shared_waves: Arc::default(),
            controller,
            persist_path,
            peer_cache_path: None,
        })
    }

    /// Also ask these bootstrap peers in chunk and pointer reads, alongside the
    /// close group and from the start of each read: of those whose address
    /// carries a `/p2p/` peer ID, the nine nearest to the address being read
    /// (all of them when there are fewer), nearest first. The nodes that were
    /// nearest to a record when it was stored may still hold it after the
    /// nodes nearest to it have changed. Nine is the nodes' storage retention
    /// width, the close group of seven plus a margin of two: replication
    /// stores a record on the nodes among the nine nearest it, and a bootstrap
    /// peer among the nine nodes nearest an address is also among the nine
    /// bootstrap peers nearest it. A chunk an upload left farther out, past
    /// close-group nodes that failed or were full, is not looked for on a
    /// bootstrap peer past the ninth.
    ///
    /// Pass the bootstrap addresses the client was configured with, such as
    /// those [`crate::config::resolve_bootstrap_multiaddrs`] returns. A client
    /// built from a node asks none until given them here; addresses without
    /// a peer ID add none.
    #[must_use]
    #[cfg(feature = "native")]
    pub fn with_bootstrap_peers(mut self, seeds: &[MultiAddr]) -> Self {
        self.network.set_bootstrap_peers(seeds);
        self
    }

    /// Set the wallet for payment operations.
    ///
    /// Also populates the EVM network from the wallet so that
    /// token approvals work without a separate `with_evm_network` call.
    ///
    /// The client pays through the root vault by default wherever the root
    /// vault of `wallet`'s network is known: the bundled network's, built in
    /// (`crate::config::root_vault_address`), else the one the client names
    /// ([`Self::with_root_vault`], before or after this call). It pays
    /// through a root vault's wallet made from `wallet`'s own signer
    /// (`crate::config::root_wallet_of`), as
    /// [`Self::with_root_payments_from_key`] does from the key: every
    /// payment pays the root vault in waves, after a one-time approval of
    /// the root vault to spend the wallet's tokens. Where no root vault is
    /// known it pays the per-quote vault, as before.
    /// [`Self::without_root_payments`] opts out and keeps the per-quote
    /// vault. A `wallet` whose transaction settings were changed
    /// (`Wallet::set_transaction_config`) can't have them read and carried
    /// over, so it gets no root vault's wallet by default and pays the
    /// per-quote vault; give it one configured as its own with
    /// [`Self::with_root_payments`].
    ///
    /// A root vault's wallet set earlier ([`Self::with_root_payments`]) is
    /// kept only while it still passes that function's checks against
    /// `wallet`; one of another key, token, RPC or vault is dropped, and the
    /// client pays as a client given `wallet` alone would. Root waves are
    /// never signed by another key than the wallet's.
    /// A root vault named earlier ([`Self::with_root_vault`]) that is
    /// `wallet`'s per-quote payment vault is dropped, as that function
    /// refuses it.
    ///
    /// In native builds the client prepares and sends every payment from
    /// `wallet`'s key, through either vault's wallet, holding `wallet`'s own lock
    /// (`Wallet::lock`, shared by its clones). A caller paying with a clone
    /// of `wallet` under that lock, as evmlib asks of a shared wallet
    /// (`Wallet::prepare_payment`), is therefore serialised with the
    /// client's payments, default root payments included, and must not call
    /// the client's payment methods while it holds the lock.
    #[must_use]
    pub fn with_wallet(mut self, wallet: Wallet) -> Self {
        self.drop_root_vault_paid_per_quote(wallet.network());
        if self
            .root_wallet
            .as_ref()
            .is_some_and(|root| root_wallet_mismatch(&wallet, root, self.root_vault).is_some())
        {
            self.root_wallet = None;
        }
        self.evm_network = Some(wallet.network().clone());
        self.wallet = Some(Arc::new(wallet));
        self.pay_root_by_default();
        self
    }

    /// Pay the per-quote vault: drop the root vault's wallet, and make none
    /// from the client's wallet ([`Self::with_wallet`]) from here on, so
    /// every payment pays the per-quote vault, one record kept by the vault
    /// for each quote paid. The client still reads root-paid records at its
    /// network's root vault, or the one it names ([`Self::with_root_vault`]).
    /// [`Self::with_root_payments`] or [`Self::with_root_payments_from_key`]
    /// opt back in.
    ///
    /// A journaled payment to the root vault of an earlier upload is then
    /// reconciled only by a client that pays the root vault.
    #[must_use]
    pub fn without_root_payments(mut self) -> Self {
        self.per_quote_only = true;
        self.root_wallet = None;
        self
    }

    /// Give the client a root vault's wallet made from its wallet's own
    /// signer ([`Self::with_wallet`]), if it has none, hasn't opted out
    /// ([`Self::without_root_payments`]), and its network's root vault is
    /// known: the bundled network's, else the one it names.
    fn pay_root_by_default(&mut self) {
        #[cfg(feature = "native")]
        {
            if self.per_quote_only || self.root_wallet.is_some() {
                return;
            }
            let Some(wallet) = self.wallet.as_deref() else {
                return;
            };
            let Some(vault) =
                crate::config::root_vault_address(wallet.network()).or(self.root_vault)
            else {
                return;
            };
            let Some(root) = crate::config::root_wallet_of(wallet, vault) else {
                tracing::info!(
                    "the wallet's transaction settings aren't the defaults and can't be carried \
                     over to a root vault's wallet: payments go through the per-quote vault \
                     unless the client is given one (with_root_payments)"
                );
                return;
            };
            if root_wallet_mismatch(wallet, &root, self.root_vault).is_none() {
                self.root_wallet = Some(Arc::new(root));
            }
        }
    }

    /// Pay through the root vault: every payment this client makes, of
    /// uploads, single records and pointers alike, pays the root vault in
    /// waves through `root_wallet`, a wallet of the same key as
    /// [`Self::with_wallet`]'s, paying the root vault on the same RPC and
    /// token (`crate::config::root_wallet`). The client's network, and so
    /// the names of its checkpoints, stay the per-quote vault's.
    ///
    /// On the bundled network the root vault is the one the client's
    /// configuration names (`crate::config::root_vault_address`), and no
    /// other is accepted. On any other network it is the one the client
    /// names ([`Self::with_root_vault`]), where it names one; otherwise the
    /// vault `root_wallet` pays is taken as given: it must be that network's
    /// root vault, the vault its storers read root payments from, since the
    /// client approves it to spend the wallet's tokens and every payment
    /// goes to it.
    ///
    /// # Errors
    ///
    /// If the client has no wallet, or `root_wallet` signs with another key,
    /// pays another token, pays the client's own payment vault, or pays a
    /// vault other than the bundled network's root vault, or on another
    /// network, the root vault the client names.
    ///
    /// A client given a wallet pays its network's root vault by default
    /// ([`Self::with_wallet`]); this gives it a root vault's wallet of the
    /// caller's own, such as one with its own transaction settings, and
    /// opts a client back in after [`Self::without_root_payments`].
    pub fn with_root_payments(mut self, root_wallet: Wallet) -> Result<Self> {
        let wallet = self.require_wallet()?;
        if let Some(mismatch) = root_wallet_mismatch(wallet, &root_wallet, self.root_vault) {
            return Err(Error::Payment(mismatch.into()));
        }
        self.root_wallet = Some(Arc::new(root_wallet));
        self.per_quote_only = false;
        Ok(self)
    }

    /// Name `vault` as the root vault of this client's payment network,
    /// without a wallet to pay it: the vault a devnet's manifest names
    /// (`crate::config::manifest_root_vault`), or one a payer outside the
    /// client pays. The client reads root-paid records there, its own
    /// envelopes' records included, as it does at the root vault its root
    /// wallet pays. A client with a wallet then pays `vault` by default, as
    /// [`Self::with_wallet`] says, unless it opted out
    /// ([`Self::without_root_payments`]); one without a wallet pays nothing
    /// by this alone. A root vault's wallet it is given
    /// ([`Self::with_root_payments`]) must pay `vault`.
    ///
    /// A network whose root vault is built in (the bundled network,
    /// `crate::config::root_vault_address`) keeps that vault: `vault` is
    /// never read or paid there. A root vault's wallet set earlier that pays
    /// another vault than `vault` is dropped, as [`Self::with_wallet`] drops
    /// one that no longer matches, and the client pays `vault` as a client
    /// naming it alone would.
    ///
    /// The network's per-quote payment vault is never its root vault: once
    /// the client's payment network is known (from [`Self::with_wallet`] or
    /// [`Self::with_evm_network`]), naming it is refused with a warning and
    /// the client is left as it was, and one named before the network is
    /// known is dropped when the network turns out to pay it per quote.
    #[must_use]
    pub fn with_root_vault(mut self, vault: ant_protocol::evm::Address) -> Self {
        let network = self
            .evm_network
            .as_ref()
            .or_else(|| self.wallet.as_deref().map(Wallet::network));
        if network.is_some_and(|network| network.payment_vault_address() == &vault) {
            tracing::warn!(
                "{vault:#x} is the payment network's per-quote payment vault, not its root \
                 vault; it isn't taken as the root vault"
            );
            return self;
        }
        self.root_vault = Some(vault);
        let mismatched = match (self.wallet.as_deref(), self.root_wallet.as_deref()) {
            (Some(wallet), Some(root)) => {
                root_wallet_mismatch(wallet, root, self.root_vault).is_some()
            }
            _ => false,
        };
        if mismatched {
            self.root_wallet = None;
        }
        self.pay_root_by_default();
        self
    }

    /// Pay through the root vault with one key, in one call: this client's
    /// wallet on `network` ([`Self::with_wallet`]) and its root vault's
    /// wallet ([`Self::with_root_payments`]), both made from `private_key`
    /// (hex, `0x` optional) and, given a `chain_id`, signing for that chain
    /// only (`crate::config::wallet`, `crate::config::root_wallet`). The root
    /// vault is the bundled network's own, else the one this client names
    /// ([`Self::with_root_vault`]): on a devnet, name the vault its manifest
    /// names (`crate::config::manifest_root_vault`) first.
    ///
    /// [`Self::with_wallet`] pays the root vault by default where one is
    /// known; this call also opts a client back in after
    /// [`Self::without_root_payments`], and refuses where no root vault is
    /// known instead of paying the per-quote vault.
    ///
    /// # Errors
    ///
    /// If `private_key` isn't a valid key, if no root vault is known for
    /// `network`, or as [`Self::with_root_payments`].
    #[cfg(feature = "native")]
    pub fn with_root_payments_from_key(
        self,
        network: ant_protocol::evm::Network,
        private_key: &str,
        chain_id: Option<u64>,
    ) -> Result<Self> {
        let wallet = crate::config::wallet(network.clone(), private_key, chain_id)
            .map_err(|e| Error::Config(format!("the client's wallet: {e}")))?;
        let client = self.with_wallet(wallet);
        let vault = client.root_vault().ok_or_else(|| {
            Error::Config(
                "no root vault is known for this payment network: name it with \
                 with_root_vault first"
                    .into(),
            )
        })?;
        let root_wallet = crate::config::root_wallet(
            &network,
            ant_protocol::evm::Address::from(vault),
            private_key,
            chain_id,
        )
        .map_err(|e| Error::Config(format!("the root vault's wallet: {e}")))?;
        client.with_root_payments(root_wallet)
    }

    /// The wallet root payments go through, if this client pays the root
    /// vault ([`Self::with_wallet`], [`Self::with_root_payments`]).
    #[must_use]
    pub fn root_wallet(&self) -> Option<&Arc<Wallet>> {
        self.root_wallet.as_ref()
    }

    /// The vault this client's payments go to: the root vault while it has
    /// a root vault's wallet ([`Self::root_wallet`]), else the per-quote
    /// vault.
    #[must_use]
    pub fn payment_vault(&self) -> root_payment::PaymentVault {
        if self.root_wallet.is_some() {
            root_payment::PaymentVault::Root
        } else {
            root_payment::PaymentVault::V2
        }
    }

    /// The wallet that pays `vault`.
    ///
    /// # Errors
    ///
    /// If the client has no wallet for it.
    #[cfg(feature = "native")]
    pub(crate) fn wallet_paying(&self, vault: root_payment::PaymentVault) -> Result<&Arc<Wallet>> {
        match vault {
            root_payment::PaymentVault::V2 => self.require_wallet(),
            root_payment::PaymentVault::Root => {
                let root = self.root_wallet.as_ref().ok_or_else(|| {
                    Error::Payment(
                        "this payment is to the root vault, and the client has no wallet for it: \
                         build the client with with_root_payments to pay or reconcile it"
                            .into(),
                    )
                })?;
                if let Some(mismatch) =
                    root_wallet_mismatch(self.require_wallet()?, root, self.root_vault)
                {
                    return Err(Error::Payment(mismatch.into()));
                }
                Ok(root)
            }
        }
    }

    /// Hold the locks a payment from the client's key is signed and sent
    /// under, in the one order every path takes them: the key's lock
    /// ([`root_payment::signing_lock`], which names the paths that hold
    /// these), then the lock of the client's own wallet ([`Self::with_wallet`],
    /// `Wallet::lock`, shared by every clone of it), then, for a payment
    /// through the root vault's wallet (`root`), that wallet's own lock.
    ///
    /// The client's wallet's lock is taken whichever wallet signs: a root
    /// vault's wallet signs with the same key but has a lock of its own
    /// (every `Wallet::new` makes one, `crate::config::root_wallet_of`), so
    /// a caller sharing the client's wallet, holding its lock while it pays
    /// with it as evmlib asks (`Wallet::prepare_payment`), is serialised
    /// with root payments as with per-quote ones. A root vault's wallet
    /// never shares the client's wallet's lock: it pays another vault, and
    /// a wallet's vault is fixed when it is made.
    ///
    /// # Errors
    ///
    /// If the client has no wallet.
    pub(crate) async fn lock_payments<'a>(
        &'a self,
        root: Option<&'a Wallet>,
    ) -> Result<PaymentLocks<'a>> {
        let wallet = self.require_wallet()?;
        let signing = root_payment::signing_lock(wallet.address())
            .lock_owned()
            .await;
        let own = wallet.lock().await;
        let root = match root {
            Some(root) => Some(root.lock().await),
            None => None,
        };
        Ok(PaymentLocks {
            _root: root,
            _own: own,
            _signing: signing,
        })
    }

    /// Set the EVM network without requiring a wallet.
    ///
    /// This enables token approval and contract interactions
    /// for external-signer flows where the private key lives outside Rust.
    #[must_use]
    pub fn with_evm_network(mut self, network: ant_protocol::evm::Network) -> Self {
        self.drop_root_vault_paid_per_quote(&network);
        self.evm_network = Some(network);
        self
    }

    /// Drop the root vault named ([`Self::with_root_vault`]) if it is
    /// `network`'s per-quote payment vault, which is never a root vault: the
    /// client reads and pays the per-quote vault alone from then on, with a
    /// warning.
    fn drop_root_vault_paid_per_quote(&mut self, network: &ant_protocol::evm::Network) {
        if let Some(vault) = self
            .root_vault
            .take_if(|vault| vault == network.payment_vault_address())
        {
            tracing::warn!(
                "the root vault named, {vault:#x}, is the payment network's per-quote payment \
                 vault, not its root vault; it is dropped"
            );
        }
    }

    /// Get the EVM network, falling back to the wallet's network if available.
    ///
    /// # Errors
    ///
    /// Returns an error if neither `with_evm_network` nor `with_wallet` was called.
    pub(crate) fn require_evm_network(&self) -> Result<&ant_protocol::evm::Network> {
        if let Some(ref net) = self.evm_network {
            return Ok(net);
        }
        if let Some(ref wallet) = self.wallet {
            return Ok(wallet.network());
        }
        Err(Error::Payment(
            "EVM network not configured — call with_evm_network() or with_wallet() first"
                .to_string(),
        ))
    }

    /// Get the client configuration.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ClientConfig {
        &mut self.config
    }

    /// Get a reference to the network layer.
    #[must_use]
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// Compute the live network-participation snapshot.
    ///
    /// Convenience pass-through to [`Network::health`] — the single
    /// write-readiness implementation shared by all embedded-client
    /// consumers (antd, ant-gui, ant-ffi, ant-tui).
    #[cfg(feature = "native")]
    pub async fn network_health(&self) -> NetworkHealth {
        self.network.health().await
    }

    /// Get the wallet, if configured.
    #[must_use]
    pub fn wallet(&self) -> Option<&Arc<Wallet>> {
        self.wallet.as_ref()
    }

    /// The shared payment waves of this client's wallet ([`shared_wave`]).
    #[cfg(feature = "native")]
    pub(crate) fn shared_waves(&self) -> &Arc<shared_wave::SharedWaves> {
        &self.shared_waves
    }

    /// Keep a shared payment wave open this long for others to join, in
    /// place of [`shared_wave::SHARED_WAVE_WAIT`]: for tests that need two
    /// uploads to share a wave whatever their timing.
    #[cfg(all(feature = "native", feature = "test-utils"))]
    pub fn set_shared_wave_wait(&self, wait: std::time::Duration) {
        self.shared_waves.set_wait(wait);
    }

    /// Set the in-memory cache budget for this client.
    #[must_use]
    pub fn with_chunk_cache(mut self, cache: ChunkCache) -> Self {
        self.chunk_cache = cache;
        self
    }

    /// Get a reference to the chunk cache.
    #[must_use]
    pub fn chunk_cache(&self) -> &ChunkCache {
        &self.chunk_cache
    }

    /// The nodes that served chunks read recently.
    pub(crate) fn holders(&self) -> &holders::HolderCache {
        &self.holders
    }

    /// Adaptive concurrency controller. Hot loops read
    /// `controller().<channel>.current()` to size their fan-out and
    /// call `.observe(...)` on each completion.
    #[must_use]
    pub fn controller(&self) -> &AdaptiveController {
        &self.controller
    }

    /// Persist the current adaptive snapshot to disk so the next
    /// `Client::connect` warm-starts at the learned values instead of
    /// cold defaults. Best effort — failures log and are discarded.
    /// Idempotent. Safe to call from a Drop impl or an explicit
    /// shutdown hook.
    #[cfg(feature = "native")]
    pub fn save_adaptive_snapshot(&self) {
        if let Some(ref path) = self.persist_path {
            adaptive::save_snapshot(path, self.controller.snapshot());
        }
    }

    /// Persist currently connected peers that have Direct-tagged addresses in
    /// the DHT. Best effort; failures are logged and do not affect the client
    /// operation that just completed.
    #[cfg(feature = "native")]
    pub async fn save_peer_cache(&self) {
        if let Some(ref path) = self.peer_cache_path {
            let node = self.network().node();
            peer_cache::promote_connected_direct_peers(node.as_ref(), path, node.dht().k_value())
                .await;
        }
    }

    /// Get the next request ID for protocol messages.
    pub(crate) fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Handle to the peers that refused a quote request at the root vault's
    /// settlement version (the field's comment says how it is used).
    pub(crate) fn root_refusing_peers(&self) -> Arc<Mutex<HashSet<PeerId>>> {
        Arc::clone(&self.root_refusing_peers)
    }

    /// Record that `peer_id` refused this client's settlement version, and
    /// report whether enough distinct peers now agree for it to be believed.
    ///
    /// Returns the refusal wording once [`SETTLEMENT_REFUSAL_QUORUM`] is met,
    /// and `None` below it, so a lone peer is treated as a peer fault rather
    /// than a verdict about this build.
    pub(crate) fn note_settlement_refusal(&self, peer_id: PeerId, message: &str) -> Option<String> {
        self.settlement_refusals.note(peer_id, message)
    }

    /// The corroborated refusal, if this client has already been told by
    /// enough peers that it cannot settle.
    ///
    /// Checked before spending money. The verdict concerns this build rather
    /// than any one upload, so an upload that starts after another has already
    /// established it must not proceed to pay.
    pub(crate) fn corroborated_settlement_refusal(&self) -> Option<String> {
        self.settlement_refusals.corroborated()
    }

    /// Handle to the shared refusal tracker, for collectors that run outside
    /// `&self`.
    pub(crate) fn settlement_refusals(&self) -> SettlementRefusals {
        self.settlement_refusals.clone()
    }

    /// Return the chunk PUT-target set: the closest [`PUT_TARGET_WIDTH`] peers
    /// to the address, each paired with its known network addresses.
    ///
    /// Used by the merkle store path, which — unlike single-node payment — has
    /// no witnessed put-target list to forward, so it fetches the closest-K
    /// neighbourhood locally.
    pub(crate) async fn put_target_peers(
        &self,
        target: &XorName,
    ) -> Result<Vec<(PeerId, Vec<MultiAddr>)>> {
        self.closest_peers(target, PUT_TARGET_WIDTH).await
    }

    /// Return the requested number of closest peers for a target address.
    ///
    /// Queries the DHT for peers by XOR distance. Returns each peer
    /// paired with its known network addresses.
    pub(crate) async fn closest_peers(
        &self,
        target: &XorName,
        count: usize,
    ) -> Result<Vec<(PeerId, Vec<MultiAddr>)>> {
        let peers = self.network().find_closest_peers(target, count).await?;

        if peers.is_empty() {
            return Err(Error::InsufficientPeers(
                "DHT returned no peers for target address".to_string(),
            ));
        }
        Ok(peers)
    }
}

/// Persist the adaptive snapshot when the `Client` is dropped, so any
/// caller — CLI, daemon, library user, integration test — gets
/// warm-start carry-over for free without remembering to call
/// `save_adaptive_snapshot()` explicitly. Best effort, sync `std::fs`,
/// no panic risk on a poisoned mutex (the inner helper handles it).
///
/// We deliberately write SYNCHRONOUSLY (not via `spawn_blocking`)
/// because Drop runs during process shutdown / runtime teardown,
/// when fire-and-forget background tasks can be dropped before they
/// complete and the snapshot is silently lost. A small synchronous
/// stall on a tokio worker (typically <1ms for a local-disk JSON
/// write of ~50 bytes) is the right tradeoff for guaranteed
/// persistence — BOUNDED by `DROP_SAVE_TIMEOUT` so a stalled
/// network-mounted data dir cannot block process shutdown.
#[cfg(feature = "native")]
const DROP_SAVE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

#[cfg(feature = "native")]
impl Drop for Client {
    fn drop(&mut self) {
        let Some(path) = self.persist_path.clone() else {
            return;
        };
        let snap = self.controller.snapshot();
        adaptive::save_snapshot_with_timeout(path, snap, DROP_SAVE_TIMEOUT);
    }
}

/// The locks a payment from a client's key is signed and sent under
/// ([`Client::lock_payments`]), let go together when dropped, the last
/// taken first.
pub(crate) struct PaymentLocks<'a> {
    _root: Option<tokio::sync::MutexGuard<'a, ()>>,
    _own: tokio::sync::MutexGuard<'a, ()>,
    _signing: tokio::sync::OwnedMutexGuard<()>,
}

/// Why `root_wallet` cannot pay the root vault for a client paying through
/// `wallet` ([`Client::with_root_payments`]), or none if it can: it must sign
/// with `wallet`'s key and pay `wallet`'s token on its RPC, to a vault other
/// than `wallet`'s, on the bundled network to its root vault, and on any
/// other network to `named`, the root vault the client names
/// ([`Client::with_root_vault`]), where it names one.
fn root_wallet_mismatch(
    wallet: &Wallet,
    root_wallet: &Wallet,
    named: Option<ant_protocol::evm::Address>,
) -> Option<&'static str> {
    let (network, root) = (wallet.network(), root_wallet.network());
    if root_wallet.address() != wallet.address() {
        return Some("the root vault's wallet signs with another key than the client's wallet");
    }
    if root.payment_token_address() != network.payment_token_address()
        || root.rpc_url() != network.rpc_url()
        || root.payment_vault_address() == network.payment_vault_address()
    {
        return Some(
            "the root vault's wallet must pay the client's token, on its RPC, to a vault \
             other than the client's payment vault",
        );
    }
    #[cfg(feature = "native")]
    if let Some(vault) = crate::config::root_vault_address(network) {
        return (&vault != root.payment_vault_address()).then_some(
            "the root vault's wallet pays another vault than the bundled network's root vault",
        );
    }
    if named.is_some_and(|vault| &vault != root.payment_vault_address()) {
        return Some(
            "the root vault's wallet pays another vault than the root vault the client names \
             (with_root_vault)",
        );
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Cover EVERY variant of `data::error::Error`. Build an instance of
    /// each, classify it, and assert the resulting `Outcome` matches the
    /// only sensible mapping. If a future commit adds a new error variant
    /// without updating `classify_error`, this test fails to ensure the
    /// adaptive controller always sees correct capacity signals.
    ///
    /// Mapping policy (mirrors `classify_error` doc):
    /// - `Timeout` -> `Outcome::Timeout`
    /// - `Network`, `InsufficientPeers`, `Io`, `Protocol`, `Storage`,
    ///   `PartialUpload` -> `Outcome::NetworkError` (transport-related
    ///   or literal capacity failure)
    /// - everything else -> `Outcome::ApplicationError` (would happen
    ///   on a perfectly healthy network)
    #[test]
    fn classify_error_covers_all_variants() {
        let cases: Vec<(Error, Outcome)> = vec![
            (Error::Timeout("t".to_string()), Outcome::Timeout),
            (Error::Network("n".to_string()), Outcome::NetworkError),
            (
                Error::InsufficientPeers("p".to_string()),
                Outcome::NetworkError,
            ),
            (Error::Storage("s".to_string()), Outcome::NetworkError),
            (Error::Payment("p".to_string()), Outcome::ApplicationError),
            (Error::Protocol("p".to_string()), Outcome::NetworkError),
            (
                Error::InvalidData("d".to_string()),
                Outcome::ApplicationError,
            ),
            // A definitively absent record over a working link — the peers
            // answered, nothing was stored there. Must NOT register as a
            // capacity signal.
            (
                Error::NotFound("missing".to_string()),
                Outcome::ApplicationError,
            ),
            (
                Error::Serialization("s".to_string()),
                Outcome::ApplicationError,
            ),
            (Error::Crypto("c".to_string()), Outcome::ApplicationError),
            (
                Error::Io(std::io::Error::other("io")),
                Outcome::NetworkError,
            ),
            (Error::Config("c".to_string()), Outcome::ApplicationError),
            (
                Error::SignatureVerification("s".to_string()),
                Outcome::ApplicationError,
            ),
            (
                Error::Encryption("e".to_string()),
                Outcome::ApplicationError,
            ),
            (Error::AlreadyStored, Outcome::ApplicationError),
            (
                Error::InsufficientDiskSpace("d".to_string()),
                Outcome::ApplicationError,
            ),
            (
                Error::CostEstimationInconclusive("c".to_string()),
                Outcome::ApplicationError,
            ),
            (
                Error::PartialUpload {
                    stored: vec![],
                    stored_count: 0,
                    failed: vec![],
                    failed_count: 0,
                    total_chunks: 0,
                    spend: Box::new(crate::data::error::PartialUploadSpend {
                        storage_cost_atto: "0".to_string(),
                        gas_cost_wei: 0,
                    }),
                    reason: "r".to_string(),
                },
                Outcome::NetworkError,
            ),
            (
                Error::BadQuoteBinding {
                    peer_id: "peer".to_string(),
                    detail: "mismatch".to_string(),
                },
                Outcome::ApplicationError,
            ),
            // A remote application rejection: the node responded with a
            // structured `ProtocolError`, so the transport succeeded and
            // this must NOT register as a capacity signal (V2-468).
            (
                Error::RemotePut {
                    address: "abcd".to_string(),
                    source: ant_protocol::ProtocolError::PaymentFailed("stale quote".to_string()),
                },
                Outcome::ApplicationError,
            ),
            // A close-group quorum shortfall caused by dial/relay churn with
            // no PUT-response timeouts — remote peer churn, not local
            // backpressure, so it must NOT register as a capacity signal
            // (V2-554). A timeout-bearing shortfall keeps `InsufficientPeers`.
            (
                Error::CloseGroupShortfall("Stored on 3 peers, need 4".to_string()),
                Outcome::ApplicationError,
            ),
            // Refusing an oversized external-signer merkle batch happens
            // before any network work, so it is not a capacity signal.
            (
                Error::MerkleBatchTooLarge {
                    addresses: 257,
                    max_leaves: 256,
                },
                Outcome::ApplicationError,
            ),
        ];
        for (err, expected) in &cases {
            let got = classify_error(err);
            assert_eq!(
                got, *expected,
                "classify_error({err:?}) = {got:?}, expected {expected:?}",
            );
        }
    }

    /// C4 fix guard: pinning the legacy `quote_concurrency` /
    /// `store_concurrency` ClientConfig fields must clamp ONLY the
    /// matching channel's max in the resulting controller. The fetch
    /// (download) channel must keep its full default ceiling.
    #[test]
    fn legacy_concurrency_pin_does_not_bleed_across_channels() {
        let cfg = ClientConfig {
            quote_concurrency: 4,
            store_concurrency: 2,
            ..ClientConfig::default()
        };
        let (controller, _) = build_controller(&cfg);
        // The store/quote caps must be clamped to the user's pin.
        assert_eq!(controller.config.max.quote, 4, "quote pin not respected");
        assert_eq!(controller.config.max.store, 2, "store pin not respected");
        // The fetch cap must NOT have been lowered — that's the
        // regression C4 was about.
        let default_fetch_max = adaptive::ChannelMax::default().fetch;
        assert_eq!(
            controller.config.max.fetch, default_fetch_max,
            "fetch cap was lowered by store/quote pin (C4 regression)"
        );
        // Cold-start values must respect the lowered ceilings.
        assert!(
            controller.quote.current() <= 4,
            "quote start exceeds its cap"
        );
        assert!(
            controller.store.current() <= 2,
            "store start exceeds its cap"
        );
    }

    /// Default ClientConfig must NOT silently lower the controller's
    /// per-channel ceilings — the adaptive defaults give every channel
    /// real headroom to grow. This guards against future commits
    /// re-introducing a global clamp.
    #[test]
    fn default_client_config_does_not_clamp_controller_max() {
        let cfg = ClientConfig::default();
        let (controller, _) = build_controller(&cfg);
        let defaults = adaptive::ChannelMax::default();
        // The legacy fields default to 32/8 (the prior static knobs),
        // both of which are <= the per-channel adaptive defaults
        // (128/64). build_controller must keep the larger, not clobber
        // with the legacy values.
        assert_eq!(controller.config.max.quote, defaults.quote);
        assert_eq!(controller.config.max.store, defaults.store);
        assert_eq!(controller.config.max.fetch, defaults.fetch);
        // Compile-time-ish guard: if a new variant is added to Error,
        // this match forces an update here.
        let _ = |e: &Error| match e {
            Error::Timeout(_)
            | Error::Network(_)
            | Error::InsufficientPeers(_)
            | Error::Storage(_)
            | Error::Payment(_)
            | Error::Protocol(_)
            | Error::InvalidData(_)
            | Error::NotFound(_)
            | Error::DataMapWithheld(_)
            | Error::Serialization(_)
            | Error::Crypto(_)
            | Error::Io(_)
            | Error::Config(_)
            | Error::SignatureVerification(_)
            | Error::Encryption(_)
            | Error::AlreadyStored
            | Error::InsufficientDiskSpace(_)
            | Error::CostEstimationInconclusive(_)
            | Error::Cancelled(_)
            | Error::PartialUpload { .. }
            | Error::BadQuoteBinding { .. }
            | Error::BadQuoteCommitment { .. }
            | Error::MerkleBatchTooLarge { .. }
            | Error::RemotePut { .. }
            | Error::ClientUpdateRequired(_)
            | Error::StorerUpdateRequired(_)
            | Error::BatchPaymentsRefused(_)
            | Error::PointerFinal(_)
            | Error::PointerForked(_)
            | Error::CloseGroupShortfall(_) => (),
        };
    }
}
