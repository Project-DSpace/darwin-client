//! Browser-facing WebRTC Direct wire profile.
//!
//! The complete application contract lives in `saorsa_transport::webrtc`; this module is
//! retained as a compatibility re-export for existing `ant-core` callers.

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

/// The browser protocol version a size-priced `quote_chunk` is sent at: one
/// above [`BROWSER_PROTOCOL_VERSION`].
///
/// A `quote_chunk` request names no settlement version, so a storer that
/// prices records by size reads one from the frame: it quotes a
/// `quote_chunk` at this version by the record's weight, and one at
/// [`BROWSER_PROTOCOL_VERSION`] as for a full chunk. It takes this version
/// for `quote_chunk` alone, with no content after the header, and advertises
/// it in hello ([`SIZE_PRICED_QUOTE_CAPABILITY`]). A storer that predates
/// size pricing can't parse a frame at this version and closes the channel,
/// so a frame at this version goes only to a storer that advertises it.
///
/// Every other request stays at [`BROWSER_PROTOCOL_VERSION`], `chunk_protocol`
/// quote requests included: their `QuoteRequestV2` carries the settlement
/// version itself, so a storer that prices by size quotes them by weight, and
/// one that predates it answers `StorerUpdateRequired` inside the response.
pub const BROWSER_QUOTE_PROTOCOL_VERSION: u16 = BROWSER_PROTOCOL_VERSION + 1;

/// Advertised in hello by a storer that takes a `quote_chunk` at
/// [`BROWSER_QUOTE_PROTOCOL_VERSION`] and quotes it by the record's weight.
pub const SIZE_PRICED_QUOTE_CAPABILITY: &str = "size_priced_quote";

/// Whether `hello` advertises [`SIZE_PRICED_QUOTE_CAPABILITY`].
#[must_use]
pub fn quotes_by_size(hello: &BrowserHello) -> bool {
    hello
        .capabilities
        .iter()
        .any(|capability| capability == SIZE_PRICED_QUOTE_CAPABILITY)
}

/// The protocol version to send `body` at: [`BROWSER_QUOTE_PROTOCOL_VERSION`]
/// for a `quote_chunk` to a storer that advertises
/// [`SIZE_PRICED_QUOTE_CAPABILITY`] (`size_priced`), and
/// [`BROWSER_PROTOCOL_VERSION`] for every other request, `chunk_protocol`
/// frames carrying a quote request included.
#[must_use]
pub fn request_version(body: &BrowserRequestBody, size_priced: bool) -> u16 {
    if size_priced && matches!(body, BrowserRequestBody::QuoteChunk { .. }) {
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

/// Parse a request as a storer that prices by size does: any request at
/// [`BROWSER_PROTOCOL_VERSION`], and at [`BROWSER_QUOTE_PROTOCOL_VERSION`] a
/// `quote_chunk` alone, with no content after its header. Returns the frame
/// (its header at [`BROWSER_PROTOCOL_VERSION`]) and the version it was sent
/// at.
///
/// # Errors
///
/// Returns an error for any other version, for any other request at
/// [`BROWSER_QUOTE_PROTOCOL_VERSION`] (a `chunk_protocol` frame among them),
/// or where [`parse_request_frame`] would.
pub fn parse_request_frame_versioned(
    frame: &[u8],
) -> Result<(BrowserRequestFrame, u16), BrowserProtocolError> {
    let current = match parse_request_frame(frame) {
        Ok(parsed) => return Ok((parsed, BROWSER_PROTOCOL_VERSION)),
        Err(error) => error,
    };
    let bounded = &frame[..frame.len().min(MAX_BROWSER_HEADER_BYTES)];
    let mut stream = serde_json::Deserializer::from_slice(bounded).into_iter::<BrowserRequest>();
    let Some(Ok(mut header)) = stream.next() else {
        return Err(current);
    };
    if header.version != BROWSER_QUOTE_PROTOCOL_VERSION
        || !matches!(header.body, BrowserRequestBody::QuoteChunk { .. })
        || header.content_length != 0
        || frame.len() != stream.byte_offset()
    {
        return Err(current);
    }
    header.version = BROWSER_PROTOCOL_VERSION;
    let frame = encode_request_frame(&header, &[])?;
    parse_request_frame(&frame).map(|parsed| (parsed, BROWSER_QUOTE_PROTOCOL_VERSION))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_protocol::{ChunkGetRequest, ChunkMessage, ChunkMessageBody, ChunkQuoteRequestV2};

    fn chunk_request(body: ChunkMessageBody) -> (BrowserRequest, Vec<u8>) {
        let content = ChunkMessage {
            request_id: 9,
            body,
        }
        .encode()
        .unwrap();
        (
            BrowserRequest::new(9, BrowserRequestBody::ChunkProtocol, content.len()),
            content,
        )
    }

    fn quote_chunk() -> BrowserRequest {
        BrowserRequest::new(
            9,
            BrowserRequestBody::QuoteChunk {
                address: "11".repeat(32),
                size: 1,
            },
            0,
        )
    }

    /// A `chunk_protocol` frame goes at the current version whatever it
    /// carries, a quote request included, since its `QuoteRequestV2` names
    /// the settlement version itself: every storer parses it. Only a
    /// `quote_chunk` to a storer that advertises size-priced quotes goes at
    /// the next version.
    #[test]
    fn only_a_quote_chunk_to_a_size_priced_storer_goes_at_the_next_version() {
        assert_eq!(BROWSER_QUOTE_PROTOCOL_VERSION, BROWSER_PROTOCOL_VERSION + 1);
        let (quote, quote_content) = chunk_request(ChunkMessageBody::QuoteRequestV2(
            ChunkQuoteRequestV2::new([1; 32], 4096),
        ));
        let (get, _) = chunk_request(ChunkMessageBody::GetRequest(ChunkGetRequest::new([1; 32])));
        for size_priced in [false, true] {
            assert_eq!(
                request_version(&quote.body, size_priced),
                BROWSER_PROTOCOL_VERSION
            );
            assert_eq!(
                request_version(&get.body, size_priced),
                BROWSER_PROTOCOL_VERSION
            );
            assert_eq!(
                request_version(&BrowserRequestBody::Hello, size_priced),
                BROWSER_PROTOCOL_VERSION
            );
        }
        assert_eq!(
            request_version(&quote_chunk().body, true),
            BROWSER_QUOTE_PROTOCOL_VERSION
        );
        assert_eq!(
            request_version(&quote_chunk().body, false),
            BROWSER_PROTOCOL_VERSION
        );

        // The chunk_protocol quote frame is the current version's, which a
        // storer at the current version alone parses.
        let frame =
            encode_request_frame_at(&quote, &quote_content, BROWSER_PROTOCOL_VERSION).unwrap();
        assert_eq!(frame, encode_request_frame(&quote, &quote_content).unwrap());
        assert!(parse_request_frame(&frame).is_ok());
        assert_eq!(
            parse_request_frame_versioned(&frame).unwrap().1,
            BROWSER_PROTOCOL_VERSION
        );
        assert!(
            encode_request_frame_at(&quote, &quote_content, BROWSER_PROTOCOL_VERSION + 2).is_err()
        );
    }

    /// A storer that prices by size takes the next version for a
    /// `quote_chunk` with no content alone, as darwin-node's does: a
    /// `chunk_protocol` frame at it, a quote request or not, is refused, as
    /// is a `quote_chunk` with content.
    #[test]
    fn a_size_priced_storer_takes_the_next_version_for_an_empty_quote_chunk_alone() {
        let frame =
            encode_request_frame_at(&quote_chunk(), &[], BROWSER_QUOTE_PROTOCOL_VERSION).unwrap();
        assert!(parse_request_frame(&frame).is_err());
        let (parsed, version) = parse_request_frame_versioned(&frame).unwrap();
        assert_eq!(version, BROWSER_QUOTE_PROTOCOL_VERSION);
        assert_eq!(parsed.request.request_id, 9);
        assert_eq!(parsed.request.version, BROWSER_PROTOCOL_VERSION);
        assert!(parsed.content.is_empty());

        for body in [
            ChunkMessageBody::QuoteRequestV2(ChunkQuoteRequestV2::new([1; 32], 4096)),
            ChunkMessageBody::GetRequest(ChunkGetRequest::new([1; 32])),
        ] {
            let (request, content) = chunk_request(body);
            let frame = encode_request_frame_at(&request, &content, BROWSER_QUOTE_PROTOCOL_VERSION)
                .unwrap();
            assert!(parse_request_frame_versioned(&frame).is_err());
        }

        let mut with_content = quote_chunk();
        with_content.version = BROWSER_QUOTE_PROTOCOL_VERSION;
        with_content.content_length = 3;
        let mut frame = serde_json::to_vec(&with_content).unwrap();
        frame.extend_from_slice(&[1, 2, 3]);
        assert!(parse_request_frame_versioned(&frame).is_err());
    }
}
