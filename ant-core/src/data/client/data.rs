//! In-memory data operations using self-encryption.
//!
//! Upload and download raw byte data. Content is encrypted via
//! convergent encryption and stored as content-addressed chunks.
//! Use this when you already have data in memory (e.g., `Bytes`).
//! For file-based streaming uploads that avoid loading the entire
//! file into memory, see the `file` module.

#[cfg(feature = "native")]
use crate::data::client::adaptive::observe_op;
#[cfg(feature = "native")]
use crate::data::client::batch::{PaymentIntent, PreparedChunk};
#[cfg(feature = "native")]
use crate::data::client::classify_error;
#[cfg(feature = "native")]
use crate::data::client::envelope::{private_shortcut_visibility, UploadEnvelope};
#[cfg(feature = "native")]
use crate::data::client::file::{ExternalPaymentInfo, PreparedUpload, Visibility};
use crate::data::client::merkle::PaymentMode;
use crate::data::client::Client;
use crate::data::error::{Error, Result};
#[cfg(feature = "native")]
use ant_protocol::compute_address;
use bytes::Bytes;
#[cfg(feature = "native")]
use futures::stream::StreamExt;
#[cfg(feature = "native")]
use self_encryption::encrypt;
use self_encryption::DataMap;
use std::num::NonZeroUsize;
#[cfg(feature = "native")]
use tracing::debug;
use tracing::info;

/// What [`Client::data_upload`] and [`Client::data_upload_with_mode`] return:
/// they are off in this build.
const DATA_UPLOAD_OFF: &str = "data_upload is off in this build: it would store \
     the content with no envelope, so the upload would have no payment record or listing. \
     Upload with file_upload, which stores a private envelope that shows every payment \
     field, or with data_prepare_upload_with_visibility and an envelope.";

/// Result of an in-memory data upload: the `DataMap` needed to retrieve the data.
#[derive(Debug, Clone)]
pub struct DataUploadResult {
    /// The data map containing chunk metadata for reconstruction.
    pub data_map: DataMap,
    /// Number of chunks stored on the network.
    pub chunks_stored: usize,
    /// Which payment mode was actually used (not just requested).
    pub payment_mode_used: PaymentMode,
}

impl Client {
    /// Off in this build: it would store the content's chunks with no
    /// envelope, so the upload would have no payment record or listing.
    /// Upload a file with `Client::file_upload`, which stores a private
    /// envelope that shows every payment field, or in-memory content with
    /// `Client::data_prepare_upload_with_visibility` and an envelope.
    ///
    /// # Errors
    ///
    /// Always returns [`Error::InvalidData`] naming those, before anything
    /// is encrypted, quoted, paid or stored.
    pub async fn data_upload(&self, _content: Bytes) -> Result<DataUploadResult> {
        Err(Error::InvalidData(DATA_UPLOAD_OFF.into()))
    }

    /// Off in this build, as [`Client::data_upload`] is, whatever `mode`.
    ///
    /// # Errors
    ///
    /// Always returns [`Error::InvalidData`], before anything is encrypted,
    /// quoted, paid or stored.
    pub async fn data_upload_with_mode(
        &self,
        _content: Bytes,
        _mode: PaymentMode,
    ) -> Result<DataUploadResult> {
        Err(Error::InvalidData(DATA_UPLOAD_OFF.into()))
    }

    /// Phase 1 of external-signer data upload: encrypt and collect quotes.
    ///
    /// Equivalent to [`Client::data_prepare_upload_with_visibility`] with a
    /// private envelope that shows every payment field
    /// ([`Visibility::default`], as [`Client::file_upload`] stores) — see
    /// that method for details.
    #[cfg(feature = "native")]
    pub async fn data_prepare_upload(&self, content: Bytes) -> Result<PreparedUpload> {
        self.data_prepare_upload_with_visibility(content, private_shortcut_visibility())
            .await
    }

    /// Phase 1 of external-signer data upload with explicit [`Visibility`] control.
    ///
    /// Encrypts in-memory data via self-encryption, then collects storage
    /// quotes for each chunk without making any on-chain payment. Returns
    /// a [`PreparedUpload`] containing the data map and a [`PaymentIntent`]
    /// with the payment details for external signing.
    ///
    /// When `visibility` is [`Visibility::Public`], the serialized `DataMap`
    /// is bundled into the payment batch as an additional chunk and its
    /// address is recorded on the returned [`PreparedUpload`]. After
    /// [`Client::finalize_upload`] succeeds, that address is surfaced via
    /// [`crate::data::client::file::FileUploadResult::data_map_address`] so
    /// the uploader can share a single address from which anyone can retrieve
    /// the data. An envelope ([`Visibility::Envelope`]) is bundled the same
    /// way ([`PreparedUpload::envelope`]); finalize stores it after every
    /// other chunk and fills in its proof record.
    ///
    /// Wave-batch payment only — the in-memory data path does not currently
    /// support merkle batching. Use [`Client::file_prepare_upload_with_visibility`]
    /// for merkle-eligible public uploads.
    ///
    /// After the caller signs and submits the payment transaction, call
    /// [`Client::finalize_upload`] with the tx hashes to complete storage.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails, DataMap serialization fails
    /// (public only), or quote collection fails.
    #[cfg(feature = "native")]
    pub async fn data_prepare_upload_with_visibility(
        &self,
        content: Bytes,
        visibility: Visibility,
    ) -> Result<PreparedUpload> {
        let content_len = content.len();
        let visibility = visibility.normalized();
        if let Visibility::Envelope(options) = &visibility {
            options
                .validate()
                .map_err(|e| Error::InvalidData(format!("invalid envelope metadata: {e}")))?;
        }
        debug!("Preparing data upload for external signing (visibility={visibility:?}, {content_len} bytes)");

        let (data_map, encrypted_chunks) = encrypt(content)
            .map_err(|e| Error::Encryption(format!("Failed to encrypt data: {e}")))?;

        let mut chunk_contents: Vec<Bytes> = encrypted_chunks
            .into_iter()
            .map(|chunk| chunk.content)
            .collect();

        info!("Data encrypted into {} chunks", chunk_contents.len());

        // For public uploads, bundle the serialized DataMap as an extra chunk
        // in the same payment batch. This lets the external signer pay for
        // the data chunks and the DataMap chunk in one flow, and lets the
        // finalize step return the DataMap's chunk address as the shareable
        // retrieval address.
        let mut envelope = None;
        let data_map_address = match visibility {
            Visibility::Private => None,
            Visibility::Public => {
                let (address, bytes) = crate::client_engine::files::public_map_record(&data_map)
                    .map_err(Error::Serialization)?;
                info!(
                    "Public upload: bundling DataMap chunk ({} bytes) at address {}",
                    bytes.len(),
                    hex::encode(address)
                );
                chunk_contents.push(bytes);
                Some(address)
            }
            Visibility::Envelope(ref options) => {
                let salt: Option<ant_listings::Salt> = (!options.readable).then(rand::random);
                let built = options
                    .envelope(&data_map, salt.as_ref())
                    .map_err(|e| Error::InvalidData(format!("cannot build the envelope: {e}")))?;
                let (address, bytes) = crate::client_engine::files::envelope_record(&built);
                info!(
                    "Envelope upload: bundling envelope chunk ({} bytes) at address {}",
                    bytes.len(),
                    hex::encode(address)
                );
                chunk_contents.push(bytes);
                let mut prepared = UploadEnvelope::new(built, salt);
                self.note_unchecked_envelope(&mut prepared);
                envelope = Some(prepared);
                options.readable.then_some(address)
            }
        };

        let chunk_count = chunk_contents.len();
        let chunks_with_addr: Vec<(Bytes, [u8; 32])> = chunk_contents
            .into_iter()
            .map(|content| {
                let address = compute_address(&content);
                (content, address)
            })
            .collect();

        let quote_limiter = self.controller().quote.clone();
        let quote_concurrency = quote_limiter.current().min(chunk_count.max(1));
        let results: Vec<([u8; 32], Result<Option<PreparedChunk>>)> =
            crate::client_engine::bounded_unordered(
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
            )
            .collect()
            .await;

        let mut prepared_chunks = Vec::with_capacity(results.len());
        let mut already_stored_addresses = Vec::new();
        for (address, result) in results {
            match result? {
                Some(prepared) => prepared_chunks.push(prepared),
                None => already_stored_addresses.push(address),
            }
        }

        if let Some(addr) = data_map_address {
            if already_stored_addresses.contains(&addr) {
                info!(
                    "Public upload: DataMap chunk {} was already stored \
                     on the network — address is retrievable without a \
                     new payment",
                    hex::encode(addr)
                );
            }
        }

        let mut payment_intent = PaymentIntent::from_prepared_chunks(&prepared_chunks);
        if envelope.is_some() {
            // The envelope's log must not be the last of its payment.
            payment_intent.sort_by_quote_hash();
        }

        info!(
            "Data prepared for external signing: {} chunks, {} already stored, total {} atto ({content_len} bytes)",
            prepared_chunks.len(),
            already_stored_addresses.len(),
            payment_intent.total_amount,
        );

        Ok(PreparedUpload {
            data_map,
            payment_info: ExternalPaymentInfo::WaveBatch {
                prepared_chunks,
                payment_intent,
            },
            data_map_address,
            already_stored_addresses,
            total_chunks: chunk_count,
            envelope,
        })
    }

    /// Store a `DataMap` on the network as a public chunk.
    ///
    /// The serialized `DataMap` is stored as a regular content-addressed chunk.
    /// Anyone who knows the returned address can retrieve and use the `DataMap`
    /// to download the original data.
    ///
    /// A raw building block: the data map is stored with no envelope, so the
    /// file's address has no payment record or listing. A file readable by
    /// address is uploaded as `darwin file upload --public` stores it, in an
    /// unlisted envelope: `Client::file_upload_public_with_mode`.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or the chunk store fails.
    pub async fn data_map_store(&self, data_map: &DataMap) -> Result<[u8; 32]> {
        let (_, serialized) = crate::client_engine::files::public_map_record(data_map)
            .map_err(Error::Serialization)?;

        info!(
            "Storing DataMap as public chunk ({} bytes serialized)",
            serialized.len()
        );

        self.chunk_put(serialized).await
    }

    /// Fetch a `DataMap` from the network by its chunk address.
    ///
    /// Retrieves the chunk at `address` and deserializes it as a `DataMap`,
    /// unwrapping it from an envelope (version 1 or 2) if it is in one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no chunk exists at `address`,
    /// [`Error::DataMapWithheld`] if it is a private file's envelope, which
    /// holds only a salted hash of the data map; other errors if retrieval or
    /// deserialization fails.
    pub async fn data_map_fetch(&self, address: &[u8; 32]) -> Result<DataMap> {
        let chunk = self.chunk_get(address).await?.ok_or_else(|| {
            Error::NotFound(format!(
                "DataMap chunk not found at {}",
                hex::encode(address)
            ))
        })?;

        decode_data_map_chunk(&chunk.content)
    }

    /// Fetch a `DataMap` from the network by trying the requested number
    /// of closest peers for the DataMap chunk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no chunk exists at `address`; other
    /// errors if retrieval or deserialization fails.
    pub async fn data_map_fetch_from_closest_peers(
        &self,
        address: &[u8; 32],
        peer_count: NonZeroUsize,
    ) -> Result<DataMap> {
        let chunk = self
            .chunk_get_from_closest_peers(address, peer_count.get())
            .await?
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "DataMap chunk not found at {}",
                    hex::encode(address)
                ))
            })?;

        decode_data_map_chunk(&chunk.content)
    }

    /// Download and decrypt data from the network using its `DataMap`.
    ///
    /// Retrieves all chunks referenced by the data map, then decrypts
    /// and reassembles the original content. Fetches chunks concurrently;
    /// the fan-out is sized by the adaptive controller's `fetch` channel
    /// and ramps up under healthy conditions.
    ///
    /// Large uploads produce a *shrunk* (child) `DataMap` whose `infos()`
    /// reference wrapper chunks rather than the root content chunks. Such a
    /// map is resolved back to its root form before download, keeping this
    /// primitive symmetric with the upload that made the map.
    ///
    /// Map resolution and network fetching are fully async and also work on a
    /// current-thread runtime.
    ///
    /// # Errors
    /// Returns the underlying fetch error, or an encryption error for invalid
    /// datamaps and content that fails verification/decryption.
    pub async fn data_download(&self, data_map: &DataMap) -> Result<Bytes> {
        self.data_download_with_concurrency(data_map, usize::MAX)
            .await
    }

    /// Download data with an upper bound on concurrent record fetches.
    pub async fn data_download_with_concurrency(
        &self,
        data_map: &DataMap,
        concurrency: usize,
    ) -> Result<Bytes> {
        if concurrency == 0 {
            return Err(Error::Config(
                "download concurrency must be positive".into(),
            ));
        }
        crate::client_engine::files::download(
            data_map,
            &|address| self.fetch_data_record(address),
            &|| self.controller().fetch.current().min(concurrency),
            &crate::runtime::sleep,
            retry_data_fetch,
        )
        .await
        .map_err(map_read_error)
    }

    /// Download a plaintext byte range. Resolves child maps first, then fetches
    /// only the records overlapping the range and decrypts them one chunk at a
    /// time, with 64-bit file arithmetic on every platform.
    /// Length is clamped at EOF; a start at or beyond EOF returns empty bytes.
    ///
    /// # Errors
    /// Returns fetch, datamap validation or decryption errors.
    pub async fn data_download_range(
        &self,
        data_map: &DataMap,
        start: usize,
        length: usize,
    ) -> Result<Bytes> {
        let fetch = |address| self.fetch_data_record(address);
        let cap = || self.controller().fetch.current();
        let root = crate::client_engine::files::resolve(data_map, &fetch, &cap)
            .await
            .map_err(map_read_error)?;
        crate::client_engine::files::read_range(
            &root,
            start as u64,
            length,
            &fetch,
            &cap,
            &crate::runtime::sleep,
            retry_data_fetch,
        )
        .await
        .map_err(map_read_error)
    }

    /// Resolve a shrunk (child) `DataMap` to the root map that lists the
    /// file's data chunks, fetching the wrapper records it points at. A map
    /// that is already a root is returned unchanged without any fetch.
    ///
    /// # Errors
    /// Returns the underlying fetch error, or an encryption error when a
    /// wrapper record does not decode to a DataMap.
    pub async fn data_map_resolve_root(&self, data_map: &DataMap) -> Result<DataMap> {
        if !data_map.is_child() {
            return Ok(data_map.clone());
        }
        let fetch = |address| async move { self.fetch_data_record(address).await };
        let cap = || self.controller().fetch.current();
        crate::client_engine::files::resolve(data_map, &fetch, &cap)
            .await
            .map_err(map_read_error)
    }

    /// Read a range through a validated index reused across browser seeks,
    /// taking records from `held` and fetching those it resolves to `None`. A
    /// record that `held` resolves to an error counts as a failed fetch
    /// attempt, which the read retries by fetching.
    #[cfg(all(feature = "browser-wasm", target_arch = "wasm32"))]
    pub(crate) async fn data_download_indexed_range<H>(
        &self,
        index: &self_encryption::DataMapIndex,
        start: u64,
        length: usize,
        held: impl Fn([u8; 32]) -> H,
    ) -> Result<Bytes>
    where
        H: std::future::Future<Output = Option<Result<Bytes>>>,
    {
        crate::client_engine::files::read_indexed_range(
            index,
            start,
            length,
            &|address| {
                let held = held(address);
                async move {
                    match held.await {
                        Some(result) => result,
                        None => self.fetch_data_record(address).await,
                    }
                }
            },
            &|| self.controller().fetch.current(),
            &crate::runtime::sleep,
            retry_data_fetch,
        )
        .await
        .map_err(map_read_error)
    }

    /// Fetch and decrypt every chunk of a file as a complete download does:
    /// within the adaptive fetch cap and `concurrency`, missing records retried
    /// together in deferred rounds. Each chunk goes to `deliver` as it arrives,
    /// in any order.
    #[cfg(all(feature = "browser-wasm", target_arch = "wasm32"))]
    pub(crate) async fn data_download_indexed_chunks(
        &self,
        index: &self_encryption::DataMapIndex,
        concurrency: usize,
        deliver: impl Fn(usize, Bytes) -> std::result::Result<(), String>,
    ) -> Result<()> {
        crate::client_engine::files::read_chunks(
            index,
            0..index.infos().len(),
            &|address| self.fetch_data_record(address),
            &|| self.controller().fetch.current().min(concurrency),
            &crate::runtime::sleep,
            retry_data_fetch,
            deliver,
        )
        .await
        .map_err(map_read_error)
    }

    /// Fetch and decrypt one chunk, retrying it on its own deferred schedule.
    #[cfg(all(feature = "browser-wasm", target_arch = "wasm32"))]
    pub(crate) async fn data_download_indexed_chunk(
        &self,
        index: &self_encryption::DataMapIndex,
        chunk: usize,
    ) -> Result<Bytes> {
        let plaintext = std::cell::Cell::new(None);
        crate::client_engine::files::read_chunks(
            index,
            chunk..chunk + 1,
            &|address| self.fetch_data_record(address),
            &|| 1,
            &crate::runtime::sleep,
            retry_data_fetch,
            |_, bytes| {
                plaintext.set(Some(bytes));
                Ok(())
            },
        )
        .await
        .map_err(map_read_error)?;
        Ok(plaintext
            .take()
            .expect("a completed pass delivers its one chunk"))
    }

    async fn fetch_data_record(&self, address: [u8; 32]) -> Result<Bytes> {
        self.chunk_get_observed(&address)
            .await?
            .map(|chunk| chunk.content)
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "Missing chunk {} required for data reconstruction",
                    hex::encode(address)
                ))
            })
    }
}

fn retry_data_fetch(error: &Error) -> bool {
    matches!(
        error,
        Error::NotFound(_)
            | Error::Timeout(_)
            | Error::Network(_)
            | Error::Protocol(_)
            | Error::Storage(_)
            | Error::Io(_)
            | Error::InsufficientPeers(_)
    )
}

pub(super) fn map_read_error(error: crate::client_engine::files::ReadError<Error>) -> Error {
    match error {
        crate::client_engine::files::ReadError::Fetch(error) => error,
        crate::client_engine::files::ReadError::Invalid(error) => Error::Encryption(error),
    }
}

fn decode_data_map_chunk(content: &[u8]) -> Result<DataMap> {
    use crate::client_engine::files::{decode_map_record, MapError};
    decode_map_record(content).map_err(|error| match error {
        MapError::Withheld => Error::DataMapWithheld(error.to_string()),
        MapError::Invalid(message) => Error::Serialization(message),
    })
}

#[cfg(all(test, feature = "native"))]
mod held_back_tests {
    use super::*;

    /// `data_upload` and `data_upload_with_mode` store no envelope, so they
    /// are off: each refuses before anything is encrypted, quoted or paid,
    /// and names what to use instead. The client has no wallet and its node
    /// was never started, so nothing could have been sent.
    #[tokio::test]
    async fn data_upload_is_held_back() {
        let network = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(std::sync::Arc::clone(network.node()), Default::default());
        let content = || Bytes::from(vec![7u8; 4096]);
        for result in [
            client.data_upload(content()).await,
            client
                .data_upload_with_mode(content(), PaymentMode::Single)
                .await,
            client
                .data_upload_with_mode(content(), PaymentMode::Auto)
                .await,
            client
                .data_upload_with_mode(content(), PaymentMode::Merkle)
                .await,
        ] {
            let error = result.expect_err("held back");
            assert!(matches!(error, Error::InvalidData(_)), "{error}");
            let text = error.to_string();
            assert!(text.contains("data_upload is off in this build"), "{text}");
            assert!(text.contains("file_upload"), "{text}");
            assert!(
                text.contains("data_prepare_upload_with_visibility"),
                "{text}"
            );
        }
    }
}

/// Compile-time assertions that Client method futures are Send.
///
/// These methods are called from axum handlers and tokio::spawn contexts
/// that require Send + 'static. The async closures inside stream
/// combinators must not capture references with concrete lifetimes
/// (HRTB issue). If any of these checks fail, the stream closures
/// need restructuring to use owned values instead of references.
#[cfg(test)]
mod send_assertions {
    use super::*;

    fn _assert_send<T: Send>(_: &T) {}

    #[allow(
        dead_code,
        unreachable_code,
        unused_variables,
        clippy::diverging_sub_expression
    )]
    async fn _data_download_is_send(client: &Client) {
        let dm: DataMap = todo!();
        let fut = client.data_download(&dm);
        _assert_send(&fut);
    }

    #[allow(
        dead_code,
        unreachable_code,
        unused_variables,
        clippy::diverging_sub_expression
    )]
    async fn _data_download_range_is_send(client: &Client) {
        let dm: DataMap = todo!();
        _assert_send(&client.data_download_range(&dm, 0, 1024));
    }

    #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
    async fn _data_upload_is_send(client: &Client) {
        let fut = client.data_upload(Bytes::new());
        _assert_send(&fut);
    }

    #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
    async fn _data_upload_with_mode_is_send(client: &Client) {
        let fut = client.data_upload_with_mode(Bytes::new(), PaymentMode::Auto);
        _assert_send(&fut);
    }

    #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
    async fn _data_prepare_upload_is_send(client: &Client) {
        let fut = client.data_prepare_upload(Bytes::new());
        _assert_send(&fut);
    }

    #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
    async fn _data_prepare_upload_with_visibility_is_send(client: &Client) {
        let fut = client.data_prepare_upload_with_visibility(Bytes::new(), Visibility::Public);
        _assert_send(&fut);
    }
}
