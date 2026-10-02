//! Shared helper for the chunk protocol request/response pattern.
//!
//! Extracts the duplicated "subscribe → send → poll event loop" into a single
//! generic function used by both `ant-client` and `ant-node` E2E helpers.

use crate::chunk::{ChunkMessage, ChunkMessageBody, CHUNK_PROTOCOL_ID};
use crate::logging::{debug, warn};
use saorsa_core::identity::PeerId;
use saorsa_core::{MultiAddr, P2PEvent, P2PNode};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;

/// A decoded chunk-protocol response together with transport provenance.
///
/// `transport_source` is supplied by the authenticated transport receive path.
/// It is diagnostic metadata, not an identity signal; `source_peer` remains
/// the authenticated application-level peer identity used by the response
/// filter.
#[derive(Debug)]
pub struct ChunkProtocolResponse<T, E> {
    /// Result produced by the caller's response handler. Keeping the result
    /// inside the envelope preserves provenance for structured remote errors.
    pub result: Result<T, E>,
    /// Authenticated peer that supplied the matching response.
    pub source_peer: PeerId,
    /// Transport address that delivered the response, when available.
    pub transport_source: Option<MultiAddr>,
}

/// Send a chunk-protocol message to `target_peer` and await a matching response.
///
/// The event loop filters by topic (`CHUNK_PROTOCOL_ID`), source peer, decode
/// errors (warn + skip), and `request_id` mismatch (skip).
///
/// * `response_handler` — inspects the decoded [`ChunkMessageBody`] and returns:
///   - `Some(Ok(T))` to resolve successfully,
///   - `Some(Err(E))` to resolve with an error,
///   - `None` to keep waiting (wrong variant / not our response).
/// * `send_error` — produces the caller's error type when `send_message` fails.
/// * `timeout_error` — produces the caller's error type on deadline expiry.
///
/// # Errors
///
/// Returns `Err(E)` if sending fails (via `send_error`), the `response_handler`
/// returns a protocol-level error, or the deadline expires (via `timeout_error`).
#[allow(clippy::too_many_arguments)]
pub async fn send_and_await_chunk_response<T, E>(
    node: &P2PNode,
    target_peer: &PeerId,
    message_bytes: Vec<u8>,
    request_id: u64,
    timeout: Duration,
    peer_addrs: &[MultiAddr],
    response_handler: impl Fn(ChunkMessageBody) -> Option<Result<T, E>>,
    send_error: impl FnOnce(String) -> E,
    timeout_error: impl FnOnce() -> E,
) -> Result<T, E> {
    send_and_await_chunk_response_with_metadata(
        node,
        target_peer,
        message_bytes,
        request_id,
        timeout,
        peer_addrs,
        response_handler,
        send_error,
        timeout_error,
    )
    .await
    .and_then(|response| response.result)
}

/// Send a chunk-protocol message and return the decoded response plus the
/// observed transport provenance.
///
/// This follows the same filtering and timeout behaviour as
/// [`send_and_await_chunk_response`]. The additional metadata is captured from
/// the already-received event and does not alter peer selection, dialing,
/// retries, or response acceptance.
///
/// # Errors
///
/// Returns `Err(E)` if sending fails (via `send_error`) or the deadline
/// expires (via `timeout_error`). A decoded protocol-level response error is
/// retained in [`ChunkProtocolResponse::result`] so its source metadata is not
/// lost.
#[allow(clippy::too_many_arguments)]
pub async fn send_and_await_chunk_response_with_metadata<T, E>(
    node: &P2PNode,
    target_peer: &PeerId,
    message_bytes: Vec<u8>,
    request_id: u64,
    timeout: Duration,
    peer_addrs: &[MultiAddr],
    response_handler: impl Fn(ChunkMessageBody) -> Option<Result<T, E>>,
    send_error: impl FnOnce(String) -> E,
    timeout_error: impl FnOnce() -> E,
) -> Result<ChunkProtocolResponse<T, E>, E> {
    // Subscribe before sending so we don't miss the response
    let mut events = node.subscribe_events();

    node.send_message(target_peer, CHUNK_PROTOCOL_ID, message_bytes, peer_addrs)
        .await
        .map_err(|e| send_error(e.to_string()))?;

    // `Instant::now() + timeout` can panic on extreme durations; fall back
    // to the current instant (immediate timeout) if the addition overflows
    // rather than taking down a crate that denies panics.
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Ok(P2PEvent::Message {
                topic,
                source: Some(source),
                transport_source,
                data,
                ..
            })) if topic == CHUNK_PROTOCOL_ID && source == *target_peer => {
                let response = match ChunkMessage::decode(&data) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Failed to decode chunk message, skipping: {e}");
                        continue;
                    }
                };
                if response.request_id != request_id {
                    continue;
                }
                if let Some(result) = response_handler(response.body) {
                    return Ok(ChunkProtocolResponse {
                        result,
                        source_peer: source,
                        transport_source,
                    });
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(RecvError::Lagged(skipped))) => {
                debug!("Chunk protocol events lagged by {skipped} messages, continuing");
            }
            Ok(Err(RecvError::Closed)) | Err(_) => break,
        }
    }

    Err(timeout_error())
}
