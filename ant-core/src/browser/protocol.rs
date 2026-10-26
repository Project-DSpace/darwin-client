//! Browser-facing WebRTC Direct wire profile.
//!
//! The complete application contract lives in `saorsa_transport::webrtc`; this module is
//! retained as a compatibility re-export for existing `ant-core` callers.

use ant_protocol::ChunkMessageBody;

pub use saorsa_transport::webrtc::{
    decode_hex, encode_request_frame, encode_response_frame, ice_password_from_sdp, normalize_hex,
    parse_request_frame, parse_request_header, parse_response_frame, parse_webrtc_direct_multiaddr,
    response_frame_length, server_answer_sdp, v2_server_ice_credential, validate_hello_metadata,
    BrowserCommitmentArtifact, BrowserEndpoint, BrowserEndpointInput, BrowserHello, BrowserNode,
    BrowserPaymentNetwork, BrowserProtocolError, BrowserQuoteArtifact, BrowserRequest,
    BrowserRequestBody, BrowserRequestFrame, BrowserResponse, BrowserResponseBody,
    BrowserResponseFrame, BrowserResponseStatus, WebRtcDirectEndpoint, BROWSER_PROTOCOL_NAME,
    BROWSER_PROTOCOL_VERSION, MAX_BROWSER_FRAME_BYTES, MAX_BROWSER_HEADER_BYTES,
    MAX_BROWSER_RECORD_BYTES, MAX_BROWSER_RESPONSE_BYTES, MAX_WEBRTC_DIRECT_MULTIADDR_LENGTH,
    WEBRTC_DIRECT_DATA_CHANNEL, WEBRTC_WRITE_CHUNK_BYTES,
};

/// The browser protocol version a quote request is sent at: one above
/// [`BROWSER_PROTOCOL_VERSION`].
///
/// A browser request names no settlement version, so a storer reads one from
/// the frame: a storer that prices records by size quotes a request at this
/// version by the record's weight, and quotes one at
/// [`BROWSER_PROTOCOL_VERSION`] as for a full chunk. A storer that predates
/// size pricing can't parse a frame at this version, so it gives no quote
/// and is never paid an amount it would refuse. Every other request (hello,
/// lookups, reads, PUTs) stays at [`BROWSER_PROTOCOL_VERSION`], so those
/// storers still serve it.
pub const BROWSER_QUOTE_PROTOCOL_VERSION: u16 = BROWSER_PROTOCOL_VERSION + 1;

/// Whether a shared ant-protocol message asks for a quote.
#[must_use]
pub fn is_quote_request(body: &ChunkMessageBody) -> bool {
    matches!(
        body,
        ChunkMessageBody::QuoteRequest(_)
            | ChunkMessageBody::QuoteRequestV2(_)
            | ChunkMessageBody::MerkleCandidateQuoteRequest(_)
            | ChunkMessageBody::MerkleCandidateQuoteRequestV2(_)
    )
}

/// The protocol version to send `body` at: [`BROWSER_QUOTE_PROTOCOL_VERSION`]
/// for `quote_chunk` and for a `chunk_protocol` frame carrying a quote
/// request (`carries_quote`), [`BROWSER_PROTOCOL_VERSION`] for the rest.
#[must_use]
pub fn request_version(body: &BrowserRequestBody, carries_quote: bool) -> u16 {
    let quote = match body {
        BrowserRequestBody::QuoteChunk { .. } => true,
        BrowserRequestBody::ChunkProtocol => carries_quote,
        _ => false,
    };
    if quote {
        BROWSER_QUOTE_PROTOCOL_VERSION
    } else {
        BROWSER_PROTOCOL_VERSION
    }
}

/// Encode `request` with `content` at `version`, which is
/// [`BROWSER_PROTOCOL_VERSION`] or [`BROWSER_QUOTE_PROTOCOL_VERSION`]. The
/// frame is checked as [`encode_request_frame`] checks it, then its header
/// names `version`.
///
/// # Errors
///
/// Returns an error for any other version, or where [`encode_request_frame`]
/// would.
pub fn encode_request_frame_at(
    request: &BrowserRequest,
    content: &[u8],
    version: u16,
) -> Result<Vec<u8>, BrowserProtocolError> {
    let mut current = request.clone();
    current.version = BROWSER_PROTOCOL_VERSION;
    let frame = encode_request_frame(&current, content)?;
    if version == BROWSER_PROTOCOL_VERSION {
        return Ok(frame);
    }
    if version != BROWSER_QUOTE_PROTOCOL_VERSION {
        return Err(BrowserProtocolError::Frame(format!(
            "cannot encode request version {version}"
        )));
    }
    current.version = version;
    let header =
        serde_json::to_vec(&current).map_err(|e| BrowserProtocolError::Frame(e.to_string()))?;
    if header.len() > MAX_BROWSER_HEADER_BYTES {
        return Err(BrowserProtocolError::Frame(format!(
            "invalid browser header length {}",
            header.len()
        )));
    }
    let mut out = Vec::with_capacity(header.len() + content.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(content);
    Ok(out)
}

/// Parse a request sent at [`BROWSER_PROTOCOL_VERSION`] or
/// [`BROWSER_QUOTE_PROTOCOL_VERSION`], as a storer that prices by size does,
/// returning the frame (its header at [`BROWSER_PROTOCOL_VERSION`]) and the
/// version it was sent at.
///
/// # Errors
///
/// Returns an error for any other version, or where [`parse_request_frame`]
/// would.
pub fn parse_request_frame_versioned(
    frame: &[u8],
) -> Result<(BrowserRequestFrame, u16), BrowserProtocolError> {
    let bounded = &frame[..frame.len().min(MAX_BROWSER_HEADER_BYTES)];
    let mut stream = serde_json::Deserializer::from_slice(bounded).into_iter::<BrowserRequest>();
    let (mut header, offset) = match stream.next() {
        Some(Ok(header)) => (header, stream.byte_offset()),
        _ => return parse_request_frame(frame).map(|f| (f, BROWSER_PROTOCOL_VERSION)),
    };
    let version = header.version;
    if version != BROWSER_QUOTE_PROTOCOL_VERSION {
        return parse_request_frame(frame).map(|f| (f, version));
    }
    header.version = BROWSER_PROTOCOL_VERSION;
    let content = &frame[offset..];
    let current = encode_request_frame(&header, content)?;
    parse_request_frame(&current).map(|f| (f, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_protocol::{ChunkGetRequest, ChunkMessage, ChunkQuoteRequestV2};

    fn chunk_request(body: ChunkMessageBody) -> (BrowserRequest, Vec<u8>, bool) {
        let quote = is_quote_request(&body);
        let content = ChunkMessage {
            request_id: 9,
            body,
        }
        .encode()
        .unwrap();
        (
            BrowserRequest::new(9, BrowserRequestBody::ChunkProtocol, content.len()),
            content,
            quote,
        )
    }

    /// A quote goes at the next version and everything else at the current
    /// one, so a storer that predates size pricing still serves reads and
    /// PUTs, and gives no quote it would not honour.
    #[test]
    fn only_quote_requests_go_at_the_next_version() {
        assert_eq!(BROWSER_QUOTE_PROTOCOL_VERSION, BROWSER_PROTOCOL_VERSION + 1);
        let (quote, quote_content, carries) = chunk_request(ChunkMessageBody::QuoteRequestV2(
            ChunkQuoteRequestV2::new([1; 32], 4096),
        ));
        assert!(carries);
        assert_eq!(
            request_version(&quote.body, carries),
            BROWSER_QUOTE_PROTOCOL_VERSION
        );
        let (get, _, carries) =
            chunk_request(ChunkMessageBody::GetRequest(ChunkGetRequest::new([1; 32])));
        assert!(!carries);
        assert_eq!(
            request_version(&get.body, carries),
            BROWSER_PROTOCOL_VERSION
        );
        assert_eq!(
            request_version(
                &BrowserRequestBody::QuoteChunk {
                    address: "11".repeat(32),
                    size: 1,
                },
                false
            ),
            BROWSER_QUOTE_PROTOCOL_VERSION
        );
        assert_eq!(
            request_version(&BrowserRequestBody::Hello, true),
            BROWSER_PROTOCOL_VERSION
        );

        // The quote frame names the next version, and a storer at the
        // current version alone can't parse it.
        let frame = encode_request_frame_at(&quote, &quote_content, BROWSER_QUOTE_PROTOCOL_VERSION)
            .unwrap();
        assert!(parse_request_frame(&frame).is_err());
        let (parsed, version) = parse_request_frame_versioned(&frame).unwrap();
        assert_eq!(version, BROWSER_QUOTE_PROTOCOL_VERSION);
        assert_eq!(parsed.content, quote_content);
        assert_eq!(parsed.request.request_id, 9);

        let plain =
            encode_request_frame_at(&quote, &quote_content, BROWSER_PROTOCOL_VERSION).unwrap();
        assert_eq!(plain, encode_request_frame(&quote, &quote_content).unwrap());
        assert_eq!(
            parse_request_frame_versioned(&plain).unwrap().1,
            BROWSER_PROTOCOL_VERSION
        );
        assert!(
            encode_request_frame_at(&quote, &quote_content, BROWSER_PROTOCOL_VERSION + 2).is_err()
        );
    }
}
