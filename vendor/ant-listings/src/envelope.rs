//! The envelope a file's data map, or a salted hash of it, is stored in.
//!
//! Layout, version 2. Fields follow each other with no padding:
//!
//! | Bytes | Field |
//! |---|---|
//! | 8 | [`MAGIC`] |
//! | 1 | version, `2` |
//! | 1 | flags, see [`Flags`] |
//! | 1 | content type length `n`; `0` means none |
//! | n | content type, printable ASCII |
//! | 1 | name length `m`; `0` means none |
//! | m | name, UTF-8 |
//! | rest | the data map, msgpack-encoded exactly as an unlisted upload stores it ([`encode_data_map`]); or, if the flags say it is withheld, exactly 32 bytes of [`salted_hash`] |
//!
//! The data map must be encoded exactly as [`encode_data_map`] encodes it,
//! with nothing after it, so each data map has one envelope for each choice
//! of flags and metadata. Its chunk indexes and sizes aren't checked against
//! the content, so a file's data map can be varied and wrapped again at
//! another address.
//!
//! Version 1 has no flags byte. It reads as all payment fields shown, in the
//! index, with the data map ([`Flags::V1`]), and re-encodes byte for byte as
//! version 1. New envelopes are always version 2.
//!
//! The envelope is stored as one chunk. Its address, `blake3(envelope)`, is the
//! file's address.

use crate::flags::{Flags, ShownFields};
use ant_protocol::{compute_address, XorName, MAX_CHUNK_SIZE};
use self_encryption::DataMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The first bytes of every envelope. They start with `0x00`, which no
/// msgpack-encoded data map can start with.
pub const MAGIC: [u8; 8] = *b"\0ANTLIST";

/// The envelope version this crate writes.
pub const ENVELOPE_VERSION: u8 = 2;

/// The first envelope version, still read.
pub const ENVELOPE_VERSION_1: u8 = 1;

/// Longest content type, in bytes.
pub const MAX_CONTENT_TYPE_LEN: usize = 127;

/// Longest name, in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// Length of the salt a withheld data map is hashed with.
pub const SALT_LEN: usize = 32;

/// Length of a withheld data map's salted hash.
pub const SALTED_HASH_LEN: usize = 32;

/// Random bytes chosen by the uploader and kept with the data map. Without
/// them, anyone who has the file could compute its data map and check it
/// against the envelope.
pub type Salt = [u8; SALT_LEN];

/// Optional, uploader-declared description of a file. It is public and
/// permanent, and nothing checks that it is true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// A media type such as `application/pdf`, optionally with parameters
    /// (`text/plain; charset=utf-8`). Printable ASCII, at most 127 bytes.
    pub content_type: Option<String>,
    /// A display name such as `report.pdf`. UTF-8, at most 255 bytes, with no
    /// control characters, no characters that reorder, split or hide text
    /// (such as right-to-left overrides, line separators and zero-width
    /// spaces), no path separators or characters that look like them, and not
    /// `.` or `..`. Joiners (as in Persian words and emoji such as 👩‍💻), soft
    /// hyphens and flags such as Scotland's are allowed. Version 1 envelopes
    /// were written under a looser rule: no control characters, `/` or `\`.
    /// Clients must still treat it as untrusted when saving files.
    pub name: Option<String>,
}

impl Metadata {
    /// Check both fields against the format rules for new envelopes
    /// (version 2). The constructors check this, and clients should before
    /// paying for an upload.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::InvalidContentType`] or
    /// [`EnvelopeError::InvalidName`] for the first rule broken.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        self.validate_under(NameRule::Version2)
    }

    /// Check both fields against version 1's rules, which allow every name
    /// version 2 allows and more. For listings with [`Flags::V1`], the only
    /// flags a version 1 envelope can have, which a version 2 envelope can
    /// have too: [`Listing::matches`](crate::Listing::matches) ties a
    /// listing's metadata to its envelope, which was checked under its own
    /// version's rules when it was parsed.
    pub(crate) fn validate_any_version(&self) -> Result<(), EnvelopeError> {
        self.validate_under(NameRule::Version1)
    }

    fn validate_under(&self, rule: NameRule) -> Result<(), EnvelopeError> {
        if let Some(content_type) = &self.content_type {
            validate_content_type(content_type)?;
        }
        if let Some(name) = &self.name {
            validate_name(name, rule)?;
        }
        Ok(())
    }

    /// Whether neither field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content_type.is_none() && self.name.is_none()
    }
}

/// Why bytes are not a valid envelope, or a reveal doesn't match one.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    /// The bytes don't start with [`MAGIC`].
    #[error("not an envelope")]
    NotAnEnvelope,
    /// A version this crate doesn't know.
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    /// The flags byte has the reserved bit 7 set.
    #[error("invalid envelope flags {0:#04x}: bit 7 is reserved")]
    InvalidFlags(u8),
    /// The bytes end before a field does.
    #[error("envelope ends early")]
    Truncated,
    /// The content type breaks a format rule.
    #[error("invalid content type: {0}")]
    InvalidContentType(&'static str),
    /// The name breaks a format rule.
    #[error("invalid name: {0}")]
    InvalidName(&'static str),
    /// The data map is missing, lists no chunks, has chunk sizes that
    /// overflow, can't be decoded, or is not encoded exactly as
    /// [`encode_data_map`] encodes it.
    #[error("invalid data map: {0}")]
    InvalidDataMap(String),
    /// A withheld data map's salted hash is not 32 bytes.
    #[error("a withheld data map's salted hash is 32 bytes, not {0}")]
    InvalidSaltedHash(usize),
    /// The envelope doesn't fit in one chunk.
    #[error("envelope is {size} bytes, more than one chunk ({max})")]
    TooLarge {
        /// Size of the envelope.
        size: usize,
        /// The chunk size limit.
        max: usize,
    },
    /// A data map was revealed for an envelope that carries its own.
    #[error("the envelope carries its data map, so there is nothing to reveal")]
    NotWithheld,
    /// The revealed data map and salt don't give the envelope's salted hash.
    #[error("the data map and salt do not match the envelope's salted hash")]
    RevealMismatch,
}

#[derive(Debug, Clone)]
enum Payload {
    /// The data map, and its bytes exactly as stored, so re-encoding gives the
    /// same bytes and therefore the same address.
    DataMap { data_map: DataMap, bytes: Vec<u8> },
    /// The data map's salted hash.
    Withheld([u8; SALTED_HASH_LEN]),
}

/// A parsed, valid envelope.
#[derive(Debug, Clone)]
pub struct Envelope {
    version: u8,
    flags: Flags,
    metadata: Metadata,
    payload: Payload,
}

impl Envelope {
    /// An envelope carrying the data map, so anyone with its address can read
    /// the file: an unlisted upload, or a listed one if `in_index`.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata breaks a format rule, the data map has
    /// no chunks or can't be encoded, or the result wouldn't fit in one chunk.
    pub fn readable(
        data_map: &DataMap,
        metadata: Metadata,
        shown: ShownFields,
        in_index: bool,
    ) -> Result<Self, EnvelopeError> {
        let bytes = encode_data_map(data_map)?;
        Self::build(
            Flags {
                shown,
                in_index,
                withheld: false,
            },
            metadata,
            Payload::DataMap {
                data_map: data_map.clone(),
                bytes,
            },
        )
    }

    /// An envelope withholding the data map: it carries the data map's
    /// [`salted_hash`] with `salt`, so the file stays unreadable until the
    /// uploader reveals both.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata breaks a format rule, or the data map
    /// has no chunks or can't be encoded.
    pub fn withheld(
        data_map: &DataMap,
        salt: &Salt,
        metadata: Metadata,
        shown: ShownFields,
        in_index: bool,
    ) -> Result<Self, EnvelopeError> {
        let bytes = encode_data_map(data_map)?;
        Self::withheld_hash(salted_hash(salt, &bytes), metadata, shown, in_index)
    }

    /// An envelope withholding the data map, from a salted hash computed with
    /// [`salted_hash`].
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata breaks a format rule.
    pub fn withheld_hash(
        salted_hash: [u8; SALTED_HASH_LEN],
        metadata: Metadata,
        shown: ShownFields,
        in_index: bool,
    ) -> Result<Self, EnvelopeError> {
        Self::build(
            Flags {
                shown,
                in_index,
                withheld: true,
            },
            metadata,
            Payload::Withheld(salted_hash),
        )
    }

    fn build(flags: Flags, metadata: Metadata, payload: Payload) -> Result<Self, EnvelopeError> {
        metadata.validate()?;
        let envelope = Self {
            version: ENVELOPE_VERSION,
            flags,
            metadata,
            payload,
        };
        let size = envelope.encoded_len();
        if size > MAX_CHUNK_SIZE {
            return Err(EnvelopeError::TooLarge {
                size,
                max: MAX_CHUNK_SIZE,
            });
        }
        Ok(envelope)
    }

    /// Parse and check an envelope of either version, such as a chunk a node
    /// is storing.
    ///
    /// This reads every envelope that was ever valid: a version 1 envelope's
    /// name is checked under version 1's looser rule, so envelopes stored
    /// before version 2 still replicate, repair and download. A node taking a
    /// new upload (a chunk that arrives with its payment proof) also calls
    /// [`check_new_upload`](Self::check_new_upload), so nobody can upload a
    /// name version 2 forbids by writing a version 1 envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not an envelope of a known version,
    /// the flags are invalid, a field is missing or breaks a format rule, or
    /// the data map or salted hash is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(EnvelopeError::TooLarge {
                size: bytes.len(),
                max: MAX_CHUNK_SIZE,
            });
        }
        let rest = bytes
            .strip_prefix(MAGIC.as_slice())
            .ok_or(EnvelopeError::NotAnEnvelope)?;
        let (&version, rest) = rest.split_first().ok_or(EnvelopeError::Truncated)?;
        let (flags, rest) = match version {
            ENVELOPE_VERSION_1 => (Flags::V1, rest),
            ENVELOPE_VERSION => {
                let (&flags, rest) = rest.split_first().ok_or(EnvelopeError::Truncated)?;
                (Flags::from_byte(flags)?, rest)
            }
            other => return Err(EnvelopeError::UnsupportedVersion(other)),
        };
        let (content_type, rest) = take_field(rest)?;
        let (name, rest) = take_field(rest)?;

        let content_type = content_type
            .map(|field| {
                String::from_utf8(field.to_vec())
                    .map_err(|_| EnvelopeError::InvalidContentType("must be printable ASCII"))
            })
            .transpose()?;
        let name = name
            .map(|field| {
                String::from_utf8(field.to_vec())
                    .map_err(|_| EnvelopeError::InvalidName("must be UTF-8"))
            })
            .transpose()?;
        let metadata = Metadata { content_type, name };
        // Version 1 envelopes are checked under the rules they were written
        // under, so every one stored before version 2 still reads.
        metadata.validate_under(if version == ENVELOPE_VERSION_1 {
            NameRule::Version1
        } else {
            NameRule::Version2
        })?;

        let payload = if flags.withheld {
            let hash = rest
                .try_into()
                .map_err(|_| EnvelopeError::InvalidSaltedHash(rest.len()))?;
            Payload::Withheld(hash)
        } else {
            Payload::DataMap {
                data_map: decode_data_map(rest)?,
                bytes: rest.to_vec(),
            }
        };
        Ok(Self {
            version,
            flags,
            metadata,
            payload,
        })
    }

    /// Check an envelope a node is taking as a new upload, one that arrives
    /// with its payment proof, against the rules for new envelopes: its
    /// metadata must follow version 2's rules ([`Metadata::validate`]),
    /// whatever its version. Envelopes [`from_bytes`](Self::from_bytes)
    /// accepts but this refuses are version 1 envelopes with a name only
    /// version 1 allows, such as one with a right-to-left override: still
    /// read when stored before version 2, never uploaded anew.
    ///
    /// Not for chunks that arrive through replication or repair, or for
    /// downloads: those may be envelopes stored before version 2.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::InvalidContentType`] or
    /// [`EnvelopeError::InvalidName`] for the first rule broken.
    pub fn check_new_upload(&self) -> Result<(), EnvelopeError> {
        self.metadata.validate()
    }

    /// The envelope's bytes, as stored in its chunk. A version 1 envelope
    /// gives back its version 1 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        if self.version != ENVELOPE_VERSION_1 {
            out.push(self.flags.to_byte());
        }
        put_field(&mut out, self.metadata.content_type.as_deref());
        put_field(&mut out, self.metadata.name.as_deref());
        out.extend_from_slice(self.payload_bytes());
        out
    }

    /// The file's address: the address of the envelope chunk.
    #[must_use]
    pub fn address(&self) -> XorName {
        compute_address(&self.to_bytes())
    }

    /// The envelope's version: [`ENVELOPE_VERSION_1`] or [`ENVELOPE_VERSION`].
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The envelope's flags. [`Flags::V1`] for a version 1 envelope.
    #[must_use]
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// The envelope's metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Whether the data map is withheld.
    #[must_use]
    pub fn is_withheld(&self) -> bool {
        self.flags.withheld
    }

    /// The data map, for downloading the file. `None` when withheld.
    #[must_use]
    pub fn data_map(&self) -> Option<&DataMap> {
        match &self.payload {
            Payload::DataMap { data_map, .. } => Some(data_map),
            Payload::Withheld(_) => None,
        }
    }

    /// The data map's bytes: what an unlisted upload of the same file stores.
    /// `None` when withheld.
    #[must_use]
    pub fn data_map_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            Payload::DataMap { bytes, .. } => Some(bytes),
            Payload::Withheld(_) => None,
        }
    }

    /// The withheld data map's salted hash. `None` when the envelope carries
    /// the data map.
    #[must_use]
    pub fn salted_hash(&self) -> Option<&[u8; SALTED_HASH_LEN]> {
        match &self.payload {
            Payload::DataMap { .. } => None,
            Payload::Withheld(hash) => Some(hash),
        }
    }

    /// The file's size in bytes, when the data map gives it directly. Data maps
    /// of files over about 12.5 MB are shrunk into child maps, and their size
    /// is only known after resolving them. `None` when withheld.
    #[must_use]
    pub fn file_size(&self) -> Option<u64> {
        let data_map = self.data_map()?;
        if data_map.is_child() {
            return None;
        }
        total_size(data_map)
    }

    /// Check a revealed data map and salt against a withheld envelope, and
    /// return the data map.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::NotWithheld`] if the envelope carries its data
    /// map, [`EnvelopeError::RevealMismatch`] if the data map and salt don't
    /// give its salted hash, or [`EnvelopeError::InvalidDataMap`] if they do
    /// but the bytes are not a valid data map encoded as [`encode_data_map`]
    /// encodes it.
    pub fn check_reveal(
        &self,
        data_map_bytes: &[u8],
        salt: &Salt,
    ) -> Result<DataMap, EnvelopeError> {
        let Payload::Withheld(expected) = &self.payload else {
            return Err(EnvelopeError::NotWithheld);
        };
        if salted_hash(salt, data_map_bytes) != *expected {
            return Err(EnvelopeError::RevealMismatch);
        }
        decode_data_map(data_map_bytes)
    }

    fn payload_bytes(&self) -> &[u8] {
        match &self.payload {
            Payload::DataMap { bytes, .. } => bytes,
            Payload::Withheld(hash) => hash,
        }
    }

    fn encoded_len(&self) -> usize {
        let field_len = |field: Option<&String>| 1 + field.map_or(0, String::len);
        let flags_len = usize::from(self.version != ENVELOPE_VERSION_1);
        MAGIC.len()
            + 1
            + flags_len
            + field_len(self.metadata.content_type.as_ref())
            + field_len(self.metadata.name.as_ref())
            + self.payload_bytes().len()
    }
}

/// Whether a chunk's bytes start like an envelope. A cheap check for every
/// stored chunk; [`Envelope::from_bytes`] does the full one.
#[must_use]
pub fn is_envelope(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC)
}

/// Whether an upload with these choices needs an envelope. It doesn't when it
/// stays out of the index, hides all five payment fields and has no metadata:
/// it is then stored as plain data, a readable upload's data map as a chunk
/// of its own, a private upload's not at all. Whether the data map is readable
/// makes no difference.
#[must_use]
pub fn needs_envelope(metadata: &Metadata, shown: ShownFields, in_index: bool) -> bool {
    in_index || shown != ShownFields::NONE || !metadata.is_empty()
}

/// The salted hash a withheld envelope carries: `blake3(salt ‖ data map)`,
/// over the data map's bytes exactly as an unlisted upload stores them (see
/// [`encode_data_map`]).
#[must_use]
pub fn salted_hash(salt: &Salt, data_map_bytes: &[u8]) -> [u8; SALTED_HASH_LEN] {
    let mut input = Vec::with_capacity(SALT_LEN + data_map_bytes.len());
    input.extend_from_slice(salt);
    input.extend_from_slice(data_map_bytes);
    compute_address(&input)
}

/// A data map's bytes exactly as an unlisted upload stores them, and as an
/// envelope carries or hashes them.
///
/// # Errors
///
/// Returns [`EnvelopeError::InvalidDataMap`] if the data map lists no chunks,
/// its chunk sizes add up to more than a `u64` holds, or it can't be encoded.
pub fn encode_data_map(data_map: &DataMap) -> Result<Vec<u8>, EnvelopeError> {
    check_data_map(data_map)?;
    rmp_serde::to_vec(data_map).map_err(|e| EnvelopeError::InvalidDataMap(e.to_string()))
}

/// Decode a data map, accepting only the bytes [`encode_data_map`] gives for
/// it: no trailing bytes and no other msgpack encoding of the same map, so
/// one data map has one envelope for each choice of flags and metadata.
fn decode_data_map(bytes: &[u8]) -> Result<DataMap, EnvelopeError> {
    if bytes.is_empty() {
        return Err(EnvelopeError::InvalidDataMap("missing".into()));
    }
    let data_map: DataMap =
        rmp_serde::from_slice(bytes).map_err(|e| EnvelopeError::InvalidDataMap(e.to_string()))?;
    if encode_data_map(&data_map)? != bytes {
        return Err(EnvelopeError::InvalidDataMap("not canonical".into()));
    }
    Ok(data_map)
}

fn check_data_map(data_map: &DataMap) -> Result<(), EnvelopeError> {
    if data_map.infos().is_empty() {
        return Err(EnvelopeError::InvalidDataMap("it lists no chunks".into()));
    }
    if total_size(data_map).is_none() {
        return Err(EnvelopeError::InvalidDataMap(
            "its chunk sizes overflow".into(),
        ));
    }
    Ok(())
}

/// The sum of the data map's chunk sizes, or `None` if it overflows. The
/// uploader chooses the sizes, so they are added with checks.
fn total_size(data_map: &DataMap) -> Option<u64> {
    data_map.infos().iter().try_fold(0u64, |total, chunk| {
        total.checked_add(u64::try_from(chunk.src_size).ok()?)
    })
}

fn take_field(bytes: &[u8]) -> Result<(Option<&[u8]>, &[u8]), EnvelopeError> {
    let (&len, rest) = bytes.split_first().ok_or(EnvelopeError::Truncated)?;
    let len = usize::from(len);
    if len == 0 {
        return Ok((None, rest));
    }
    if rest.len() < len {
        return Err(EnvelopeError::Truncated);
    }
    let (field, rest) = rest.split_at(len);
    Ok((Some(field), rest))
}

fn put_field(out: &mut Vec<u8>, field: Option<&str>) {
    match field {
        // Validation caps both fields at 255 bytes, so the length fits.
        Some(field) => {
            out.push(u8::try_from(field.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(field.as_bytes());
        }
        None => out.push(0),
    }
}

fn validate_content_type(content_type: &str) -> Result<(), EnvelopeError> {
    use EnvelopeError::InvalidContentType as Invalid;
    if content_type.is_empty() || content_type.len() > MAX_CONTENT_TYPE_LEN {
        return Err(Invalid("must be 1 to 127 bytes"));
    }
    if !content_type.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Invalid("must be printable ASCII"));
    }
    let essence = content_type.split(';').next().unwrap_or_default();
    match essence.split_once('/') {
        Some((kind, subtype)) if is_token(kind) && is_token(subtype) => Ok(()),
        _ => Err(Invalid("must be type/subtype")),
    }
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
}

/// Which envelope version's name rule to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameRule {
    /// Version 1: no control characters, `/` or `\`.
    Version1,
    /// Version 2, for new envelopes: version 1's, and no characters that
    /// reorder, split or hide text, no path separator look-alikes, and not
    /// `.` or `..`.
    Version2,
}

fn validate_name(name: &str, rule: NameRule) -> Result<(), EnvelopeError> {
    use EnvelopeError::InvalidName as Invalid;
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Invalid("must be 1 to 255 bytes"));
    }
    if name.chars().any(char::is_control) {
        return Err(Invalid("must not contain control characters"));
    }
    if rule == NameRule::Version1 {
        if name.contains(['/', '\\']) {
            return Err(Invalid("must not contain path separators"));
        }
        return Ok(());
    }
    if name.chars().any(is_forbidden_format_character) {
        return Err(Invalid(
            "must not contain invisible format or line separator characters",
        ));
    }
    if !tags_only_in_flags(name) {
        return Err(Invalid("must not contain tag characters outside a flag"));
    }
    if name.contains(PATH_SEPARATORS) {
        return Err(Invalid("must not contain path separators"));
    }
    if name == "." || name == ".." {
        return Err(Invalid("must not be . or .."));
    }
    Ok(())
}

/// Path separators, and the characters that look like them: slashes and
/// backslashes in other sizes, weights and widths, mathematical and
/// box-drawing diagonals, and a punctuation mark drawn as a slash.
const PATH_SEPARATORS: [char; 19] = [
    '/',         // SOLIDUS
    '\\',        // REVERSE SOLIDUS
    '\u{1735}',  // PHILIPPINE SINGLE PUNCTUATION
    '\u{2044}',  // FRACTION SLASH
    '\u{2215}',  // DIVISION SLASH
    '\u{2216}',  // SET MINUS
    '\u{2571}',  // BOX DRAWINGS LIGHT DIAGONAL UPPER RIGHT TO LOWER LEFT
    '\u{2572}',  // BOX DRAWINGS LIGHT DIAGONAL UPPER LEFT TO LOWER RIGHT
    '\u{27CB}',  // MATHEMATICAL RISING DIAGONAL
    '\u{27CD}',  // MATHEMATICAL FALLING DIAGONAL
    '\u{29F5}',  // REVERSE SOLIDUS OPERATOR
    '\u{29F8}',  // BIG SOLIDUS
    '\u{29F9}',  // BIG REVERSE SOLIDUS
    '\u{2E4A}',  // DOTTED SOLIDUS
    '\u{FE68}',  // SMALL REVERSE SOLIDUS
    '\u{FF0F}',  // FULLWIDTH SOLIDUS
    '\u{FF3C}',  // FULLWIDTH REVERSE SOLIDUS
    '\u{1F67C}', // VERY HEAVY SOLIDUS
    '\u{1F67D}', // VERY HEAVY REVERSE SOLIDUS
];

/// Whether `c` is a format, line separator or paragraph separator character
/// (Unicode general categories Cf, Zl and Zp, as of Unicode 16) that a name
/// may not contain. These reorder the text around them, break it, or are
/// invisible: a right-to-left override shows `invoice\u{202E}fdp.exe` as
/// `invoiceexe.pdf`.
///
/// Three kinds of Cf character are allowed, since ordinary names need them
/// and they neither reorder nor split text: the soft hyphen (U+00AD); the
/// zero-width non-joiner and joiner (U+200C, U+200D), part of the spelling of
/// everyday Persian and Indic words and of emoji such as 👩‍💻; and tag
/// characters (U+E0020 to U+E007F), in flags only (see
/// [`tags_only_in_flags`]).
fn is_forbidden_format_character(c: char) -> bool {
    matches!(
        c,
        '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'
            | '\u{200E}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
    )
}

/// U+1F3F4 WAVING BLACK FLAG: the base of a flag spelled with tag characters.
const TAG_BASE: char = '\u{1F3F4}';

/// U+E007F CANCEL TAG: the end of a flag spelled with tag characters.
const TAG_END: char = '\u{E007F}';

/// The longest run of tag characters in a flag: a subdivision code such as
/// `gbsct` has at most 7 letters and digits.
const MAX_TAG_RUN: usize = 7;

/// Whether every tag character (U+E0020 to U+E007F) in `name` is part of a
/// flag, such as Scotland's: [`TAG_BASE`], then 1 to [`MAX_TAG_RUN`] tag
/// digits and lower-case letters, then [`TAG_END`]. Anywhere else, tag
/// characters are invisible copies of ASCII that would hide text in the
/// name.
fn tags_only_in_flags(name: &str) -> bool {
    let mut previous = None;
    // How many tag letters and digits since the base, while in a flag.
    let mut run: Option<usize> = None;
    for c in name.chars() {
        if matches!(c, '\u{E0030}'..='\u{E0039}' | '\u{E0061}'..='\u{E007A}') {
            let count = match run {
                Some(count) => count + 1,
                None if previous == Some(TAG_BASE) => 1,
                None => return false,
            };
            if count > MAX_TAG_RUN {
                return false;
            }
            run = Some(count);
        } else if c == TAG_END {
            if run.take().is_none() {
                return false;
            }
        } else if ('\u{E0020}'..='\u{E007E}').contains(&c) || run.is_some() {
            return false;
        }
        previous = Some(c);
    }
    run.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::PaymentField;
    use crate::test_support::{data_map, metadata};

    const SALT: Salt = [0x5a; SALT_LEN];

    /// Every metadata combination the tests use.
    fn metadatas() -> Vec<Metadata> {
        vec![
            Metadata::default(),
            metadata(Some("text/plain; charset=utf-8"), None),
            metadata(None, Some("notes.txt")),
            metadata(Some("a/b"), Some("Ünïcødé name.txt")),
        ]
    }

    /// Hand-built version 1 bytes, as the first release wrote them.
    fn v1_bytes(map: &DataMap, metadata: &Metadata) -> Vec<u8> {
        let mut bytes = b"\0ANTLIST\x01".to_vec();
        put_field(&mut bytes, metadata.content_type.as_deref());
        put_field(&mut bytes, metadata.name.as_deref());
        bytes.extend_from_slice(&rmp_serde::to_vec(map).unwrap());
        bytes
    }

    #[test]
    fn readable_envelopes_round_trip() {
        let map = data_map(&[100, 100, 98]);
        for metadata in metadatas() {
            for shown in ShownFields::every() {
                for in_index in [false, true] {
                    let envelope =
                        Envelope::readable(&map, metadata.clone(), shown, in_index).unwrap();
                    let bytes = envelope.to_bytes();
                    let parsed = Envelope::from_bytes(&bytes).unwrap();
                    assert_eq!(parsed.to_bytes(), bytes);
                    assert_eq!(parsed.version(), ENVELOPE_VERSION);
                    assert_eq!(
                        parsed.flags(),
                        Flags {
                            shown,
                            in_index,
                            withheld: false
                        }
                    );
                    assert!(!parsed.is_withheld());
                    assert_eq!(parsed.metadata(), &metadata);
                    assert_eq!(parsed.data_map(), Some(&map));
                    assert_eq!(parsed.salted_hash(), None);
                    assert_eq!(parsed.file_size(), Some(298));
                    assert_eq!(parsed.address(), compute_address(&bytes));
                    assert_eq!(parsed.address(), envelope.address());
                }
            }
        }
    }

    #[test]
    fn withheld_envelopes_round_trip() {
        let map = data_map(&[100, 100, 98]);
        let map_bytes = encode_data_map(&map).unwrap();
        for metadata in metadatas() {
            for shown in ShownFields::every() {
                for in_index in [false, true] {
                    let envelope =
                        Envelope::withheld(&map, &SALT, metadata.clone(), shown, in_index).unwrap();
                    let bytes = envelope.to_bytes();
                    let parsed = Envelope::from_bytes(&bytes).unwrap();
                    assert_eq!(parsed.to_bytes(), bytes);
                    assert_eq!(
                        parsed.flags(),
                        Flags {
                            shown,
                            in_index,
                            withheld: true
                        }
                    );
                    assert!(parsed.is_withheld());
                    assert_eq!(parsed.metadata(), &metadata);
                    assert_eq!(parsed.data_map(), None);
                    assert_eq!(parsed.data_map_bytes(), None);
                    assert_eq!(parsed.file_size(), None);
                    assert_eq!(parsed.salted_hash(), Some(&salted_hash(&SALT, &map_bytes)));
                    assert_eq!(parsed.address(), compute_address(&bytes));
                }
            }
        }
    }

    #[test]
    fn every_flags_byte_in_an_envelope() {
        let map = data_map(&[1, 2, 3]);
        let map_bytes = encode_data_map(&map).unwrap();
        let hash = salted_hash(&SALT, &map_bytes);
        for byte in 0..=u8::MAX {
            let withheld = byte & Flags::WITHHELD != 0;
            let mut bytes = b"\0ANTLIST\x02".to_vec();
            bytes.push(byte);
            bytes.extend_from_slice(b"\x03a/b\x00");
            bytes.extend_from_slice(if withheld { &hash } else { &map_bytes });
            let parsed = Envelope::from_bytes(&bytes);
            if byte & Flags::RESERVED != 0 {
                assert_eq!(parsed.unwrap_err(), EnvelopeError::InvalidFlags(byte));
                continue;
            }
            let parsed = parsed.unwrap();
            assert_eq!(parsed.flags().to_byte(), byte);
            assert_eq!(parsed.to_bytes(), bytes, "{byte:#04x}");
            assert_eq!(parsed.is_withheld(), withheld);
            assert_eq!(parsed.data_map().is_some(), !withheld);
            assert_eq!(parsed.metadata().content_type.as_deref(), Some("a/b"));
            if withheld {
                assert_eq!(parsed.check_reveal(&map_bytes, &SALT).unwrap(), map);
            }
        }
    }

    #[test]
    fn layout_is_fixed() {
        let map = data_map(&[1, 1, 1]);
        let map_bytes = rmp_serde::to_vec(&map).unwrap();
        let shown = ShownFields::ALL.without(PaymentField::Quote);

        let bytes = Envelope::readable(&map, metadata(Some("a/b"), Some("n")), shown, true)
            .unwrap()
            .to_bytes();
        let mut expected = b"\0ANTLIST\x02\x2f\x03a/b\x01n".to_vec();
        expected.extend_from_slice(&map_bytes);
        assert_eq!(bytes, expected);

        let bytes = Envelope::withheld(&map, &SALT, Metadata::default(), ShownFields::ALL, false)
            .unwrap()
            .to_bytes();
        let mut expected = b"\0ANTLIST\x02\x5f\x00\x00".to_vec();
        let mut hashed = SALT.to_vec();
        hashed.extend_from_slice(&map_bytes);
        expected.extend_from_slice(&compute_address(&hashed));
        assert_eq!(bytes, expected);
    }

    #[test]
    fn version_1_envelopes_still_read() {
        let map = data_map(&[100, 100, 98]);
        for metadata in metadatas() {
            let bytes = v1_bytes(&map, &metadata);
            let parsed = Envelope::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.version(), ENVELOPE_VERSION_1);
            assert_eq!(parsed.flags(), Flags::V1);
            assert_eq!(parsed.metadata(), &metadata);
            assert_eq!(parsed.data_map(), Some(&map));
            assert_eq!(parsed.file_size(), Some(298));
            assert_eq!(parsed.to_bytes(), bytes);
            assert_eq!(parsed.address(), compute_address(&bytes));
            // Written anew, the same file is a version 2 envelope.
            let v2 = Envelope::readable(&map, metadata, ShownFields::ALL, true).unwrap();
            assert_ne!(v2.address(), parsed.address());
        }
    }

    #[test]
    fn data_map_bytes_are_what_an_unlisted_upload_stores() {
        let map = data_map(&[1, 2, 3]);
        let envelope =
            Envelope::readable(&map, Metadata::default(), ShownFields::ALL, false).unwrap();
        let unlisted = rmp_serde::to_vec(&map).unwrap();
        assert_eq!(envelope.data_map_bytes(), Some(unlisted.as_slice()));
        assert_eq!(encode_data_map(&map).unwrap(), unlisted);
    }

    #[test]
    fn a_plain_data_map_is_not_an_envelope() {
        let map_bytes = rmp_serde::to_vec(&data_map(&[1, 2, 3])).unwrap();
        assert!(!is_envelope(&map_bytes));
        assert_eq!(
            Envelope::from_bytes(&map_bytes).unwrap_err(),
            EnvelopeError::NotAnEnvelope
        );
    }

    #[test]
    fn rejects_data_maps_whose_size_overflows() {
        let fits = data_map(&[usize::MAX]);
        let envelope =
            Envelope::readable(&fits, Metadata::default(), ShownFields::ALL, true).unwrap();
        assert_eq!(envelope.file_size(), u64::try_from(usize::MAX).ok());

        let overflows = data_map(&[usize::MAX, 2]);
        let invalid = EnvelopeError::InvalidDataMap("its chunk sizes overflow".into());
        assert_eq!(encode_data_map(&overflows).unwrap_err(), invalid);
        assert_eq!(
            Envelope::readable(&overflows, Metadata::default(), ShownFields::ALL, true)
                .unwrap_err(),
            invalid
        );
        assert_eq!(
            Envelope::withheld(
                &overflows,
                &SALT,
                Metadata::default(),
                ShownFields::ALL,
                true
            )
            .unwrap_err(),
            invalid
        );
        // Stored by someone else, it doesn't parse, so no listing can be
        // made from it.
        let map_bytes = rmp_serde::to_vec(&overflows).unwrap();
        for header in [&b"\0ANTLIST\x01\x00\x00"[..], b"\0ANTLIST\x02\x3f\x00\x00"] {
            let mut bytes = header.to_vec();
            bytes.extend_from_slice(&map_bytes);
            assert_eq!(Envelope::from_bytes(&bytes).unwrap_err(), invalid);
        }
        // And a withheld one can't reveal it.
        let hidden = Envelope::withheld_hash(
            salted_hash(&SALT, &map_bytes),
            Metadata::default(),
            ShownFields::ALL,
            false,
        )
        .unwrap();
        assert_eq!(hidden.check_reveal(&map_bytes, &SALT).unwrap_err(), invalid);
    }

    #[test]
    fn data_maps_must_be_canonical() {
        let map = data_map(&[1, 2, 3]);
        let canonical = encode_data_map(&map).unwrap();
        let not_canonical = EnvelopeError::InvalidDataMap("not canonical".into());

        // The same data map as a msgpack map, not an array.
        let named = rmp_serde::to_vec_named(&map).unwrap();
        assert_ne!(named, canonical);
        assert_eq!(rmp_serde::from_slice::<DataMap>(&named).unwrap(), map);
        // The same data map with an integer, its format version, encoded
        // wider than needed: `0x01` becomes `0xcc 0x01`.
        let mut wide = canonical.clone();
        let at = wide.iter().position(|&b| b == 0x01).unwrap();
        wide.splice(at..=at, [0xcc, 0x01]);
        assert_eq!(rmp_serde::from_slice::<DataMap>(&wide).unwrap(), map);

        for header in [&b"\0ANTLIST\x01\x00\x00"[..], b"\0ANTLIST\x02\x3f\x00\x00"] {
            for other in [&named, &wide] {
                let mut bytes = header.to_vec();
                bytes.extend_from_slice(other);
                assert_eq!(Envelope::from_bytes(&bytes).unwrap_err(), not_canonical);
            }
        }

        // A reveal must be canonical too, even when the uploader hashed the
        // other bytes.
        for other in [&named, &wide] {
            let envelope = Envelope::withheld_hash(
                salted_hash(&SALT, other),
                Metadata::default(),
                ShownFields::ALL,
                false,
            )
            .unwrap();
            assert_eq!(
                envelope.check_reveal(other, &SALT).unwrap_err(),
                not_canonical
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let map = data_map(&[1, 1, 1]);
        let map_bytes = encode_data_map(&map).unwrap();
        let readable = [
            v1_bytes(&map, &metadata(Some("a/b"), Some("n"))),
            Envelope::readable(&map, Metadata::default(), ShownFields::ALL, true)
                .unwrap()
                .to_bytes(),
        ];
        let withheld = Envelope::withheld(&map, &SALT, Metadata::default(), ShownFields::ALL, true)
            .unwrap()
            .to_bytes();
        for byte in 0..=u8::MAX {
            for bytes in &readable {
                let mut extended = bytes.clone();
                extended.push(byte);
                assert_eq!(
                    Envelope::from_bytes(&extended).unwrap_err(),
                    EnvelopeError::InvalidDataMap("not canonical".into()),
                    "{byte:#04x} appended"
                );
            }
            let mut extended = withheld.clone();
            extended.push(byte);
            assert_eq!(
                Envelope::from_bytes(&extended).unwrap_err(),
                EnvelopeError::InvalidSaltedHash(SALTED_HASH_LEN + 1)
            );

            // A reveal with a byte after the data map, hashed as such.
            let mut junk = map_bytes.clone();
            junk.push(byte);
            let envelope = Envelope::withheld_hash(
                salted_hash(&SALT, &junk),
                Metadata::default(),
                ShownFields::ALL,
                false,
            )
            .unwrap();
            assert!(matches!(
                envelope.check_reveal(&junk, &SALT),
                Err(EnvelopeError::InvalidDataMap(_))
            ));
        }
        // Many junk bytes, as a whole chunk's worth of payload would be.
        let mut padded = readable[1].clone();
        padded.extend_from_slice(&[0x5a; 16]);
        assert!(matches!(
            Envelope::from_bytes(&padded),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
    }

    #[test]
    fn shrunk_data_maps_have_no_direct_size() {
        let child = DataMap::with_child(data_map(&[10, 10, 10]).infos().to_vec(), 1);
        let envelope =
            Envelope::readable(&child, Metadata::default(), ShownFields::ALL, true).unwrap();
        assert_eq!(envelope.file_size(), None);
    }

    #[test]
    fn rejects_unknown_versions() {
        let map = data_map(&[1, 1, 1]);
        let mut bytes = Envelope::readable(&map, Metadata::default(), ShownFields::ALL, true)
            .unwrap()
            .to_bytes();
        for version in [0, 3, 0x7f, 0xff] {
            bytes[8] = version;
            assert_eq!(
                Envelope::from_bytes(&bytes).unwrap_err(),
                EnvelopeError::UnsupportedVersion(version)
            );
        }
    }

    #[test]
    fn rejects_every_truncation() {
        let map = data_map(&[1, 1, 1]);
        let meta = metadata(Some("a/b"), Some("n"));
        let mut envelopes = vec![v1_bytes(&map, &meta), v1_bytes(&map, &Metadata::default())];
        for meta in [meta, Metadata::default()] {
            for in_index in [false, true] {
                envelopes.push(
                    Envelope::readable(&map, meta.clone(), ShownFields::ALL, in_index)
                        .unwrap()
                        .to_bytes(),
                );
                envelopes.push(
                    Envelope::withheld(&map, &SALT, meta.clone(), ShownFields::NONE, in_index)
                        .unwrap()
                        .to_bytes(),
                );
            }
        }
        for bytes in envelopes {
            assert!(Envelope::from_bytes(&bytes).is_ok());
            for len in 0..bytes.len() {
                assert!(
                    Envelope::from_bytes(&bytes[..len]).is_err(),
                    "a {len}-byte prefix of {bytes:?} parsed"
                );
            }
        }
    }

    #[test]
    fn a_withheld_payload_is_exactly_32_bytes() {
        let header = b"\0ANTLIST\x02\x40\x00\x00";
        for len in 0..=100 {
            let mut bytes = header.to_vec();
            bytes.extend(std::iter::repeat_n(7u8, len));
            let parsed = Envelope::from_bytes(&bytes);
            if len == SALTED_HASH_LEN {
                assert_eq!(parsed.unwrap().salted_hash(), Some(&[7; 32]));
            } else {
                assert_eq!(parsed.unwrap_err(), EnvelopeError::InvalidSaltedHash(len));
            }
        }
        // A data map in a withheld envelope is the wrong length too.
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&encode_data_map(&data_map(&[1, 1, 1])).unwrap());
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::InvalidSaltedHash(_))
        ));
        // And 32 bytes of hash in a readable one is not a data map.
        let mut bytes = b"\0ANTLIST\x02\x00\x00\x00".to_vec();
        bytes.extend_from_slice(&[7; 32]);
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
    }

    #[test]
    fn reveals_are_checked() {
        let map = data_map(&[1, 2, 3]);
        let map_bytes = encode_data_map(&map).unwrap();
        let envelope =
            Envelope::withheld(&map, &SALT, Metadata::default(), ShownFields::ALL, false).unwrap();
        assert_eq!(envelope.check_reveal(&map_bytes, &SALT).unwrap(), map);

        let mut wrong_salt = SALT;
        wrong_salt[31] ^= 1;
        assert_eq!(
            envelope.check_reveal(&map_bytes, &wrong_salt).unwrap_err(),
            EnvelopeError::RevealMismatch
        );
        let other_map = encode_data_map(&data_map(&[1, 2, 4])).unwrap();
        assert_eq!(
            envelope.check_reveal(&other_map, &SALT).unwrap_err(),
            EnvelopeError::RevealMismatch
        );
        let mut extended = map_bytes.clone();
        extended.push(0);
        assert_eq!(
            envelope.check_reveal(&extended, &SALT).unwrap_err(),
            EnvelopeError::RevealMismatch
        );

        // A hash of bytes that are not a data map matches but is refused.
        let junk = b"not a data map";
        let junk_envelope = Envelope::withheld_hash(
            salted_hash(&SALT, junk),
            Metadata::default(),
            ShownFields::ALL,
            false,
        )
        .unwrap();
        assert!(matches!(
            junk_envelope.check_reveal(junk, &SALT),
            Err(EnvelopeError::InvalidDataMap(_))
        ));

        let readable =
            Envelope::readable(&map, Metadata::default(), ShownFields::ALL, false).unwrap();
        assert_eq!(
            readable.check_reveal(&map_bytes, &SALT).unwrap_err(),
            EnvelopeError::NotWithheld
        );
    }

    #[test]
    fn salted_hash_is_blake3_of_salt_then_data_map() {
        // BLAKE3 of no input, so the hash is known to be BLAKE3.
        assert_eq!(
            compute_address(b""),
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62
            ]
        );
        let map_bytes = b"data map bytes";
        let mut input = SALT.to_vec();
        input.extend_from_slice(map_bytes);
        assert_eq!(salted_hash(&SALT, map_bytes), compute_address(&input));
        assert_ne!(
            salted_hash(&[0; 32], map_bytes),
            salted_hash(&SALT, map_bytes)
        );
    }

    #[test]
    fn envelopes_are_needed_unless_nothing_would_be_in_one() {
        let named = metadata(None, Some("n"));
        let typed = metadata(Some("a/b"), None);
        for shown in ShownFields::every() {
            for in_index in [false, true] {
                for meta in [Metadata::default(), named.clone(), typed.clone()] {
                    let expected =
                        in_index || shown != ShownFields::NONE || meta != Metadata::default();
                    assert_eq!(needs_envelope(&meta, shown, in_index), expected);
                }
            }
        }
        assert!(!needs_envelope(
            &Metadata::default(),
            ShownFields::NONE,
            false
        ));
        assert!(needs_envelope(
            &Metadata::default(),
            ShownFields::ALL,
            false
        ));
        assert!(Metadata::default().is_empty());
        assert!(!named.is_empty() && !typed.is_empty());
    }

    #[test]
    fn withheld_hash_matches_withheld() {
        let map = data_map(&[1, 2, 3]);
        let hash = salted_hash(&SALT, &encode_data_map(&map).unwrap());
        let meta = metadata(None, Some("n"));
        let a = Envelope::withheld(&map, &SALT, meta.clone(), ShownFields::NONE, true).unwrap();
        let b = Envelope::withheld_hash(hash, meta, ShownFields::NONE, true).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn rejects_bad_data_maps() {
        let mut bytes = b"\0ANTLIST\x02\x00\x00\x00".to_vec();
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
        bytes.extend_from_slice(b"not a data map");
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
        let empty = DataMap::new(Vec::new());
        assert!(matches!(
            Envelope::readable(&empty, Metadata::default(), ShownFields::ALL, true),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
        assert!(matches!(
            Envelope::withheld(&empty, &SALT, Metadata::default(), ShownFields::ALL, true),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
        let mut v1 = b"\0ANTLIST\x01\x00\x00".to_vec();
        assert!(matches!(
            Envelope::from_bytes(&v1),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
        v1.extend_from_slice(&rmp_serde::to_vec(&empty).unwrap());
        assert!(matches!(
            Envelope::from_bytes(&v1),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
    }

    #[test]
    fn rejects_oversized_envelopes() {
        let bytes = vec![0u8; MAX_CHUNK_SIZE + 1];
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::TooLarge { .. })
        ));
        let huge = data_map(&vec![1; 70_000]);
        assert!(matches!(
            Envelope::readable(&huge, Metadata::default(), ShownFields::ALL, true),
            Err(EnvelopeError::TooLarge { .. })
        ));
        // Withheld, the same data map fits: only its hash is stored.
        assert!(
            Envelope::withheld(&huge, &SALT, Metadata::default(), ShownFields::ALL, true).is_ok()
        );
    }

    #[test]
    fn content_type_rules() {
        for good in [
            "application/pdf",
            "text/plain; charset=utf-8",
            "image/svg+xml",
            "application/vnd.ms-excel",
        ] {
            assert!(validate_content_type(good).is_ok(), "{good}");
        }
        let too_long = format!("a/{}", "b".repeat(126));
        for bad in [
            "",
            "pdf",
            "/pdf",
            "application/",
            "text /plain",
            "text/pl ain",
            "text/plain\n",
            "tëxt/plain",
            too_long.as_str(),
        ] {
            assert!(validate_content_type(bad).is_err(), "{bad:?}");
        }
    }

    /// Names version 2 allows that the first version 2 rule refused: joiners
    /// in emoji and in Persian and Indic words, soft hyphens and flags.
    const JOINED_NAMES: [&str; 7] = [
        // 👩‍💻 notes.txt
        "\u{1F469}\u{200D}\u{1F4BB} notes.txt",
        // 👨‍👩‍👧.jpg
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.jpg",
        // می‌خواهم.txt, with a zero-width non-joiner as Persian spells it.
        "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}.txt",
        // A Devanagari conjunct shown half-formed with a zero-width joiner.
        "\u{0915}\u{094D}\u{200D}\u{0937}.txt",
        "soft\u{AD}hyphen.txt",
        // The flag of Scotland: black flag, tags g b s c t, cancel tag.
        "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F} trip.jpg",
        "a\u{200D}b",
    ];

    /// Names only version 1's rule allows.
    const VERSION_1_ONLY_NAMES: [&str; 9] = [
        ".",
        "..",
        "a\u{FF0F}b",
        "a\u{2215}b",
        "invoice\u{202E}fdp.exe",
        "zero\u{200B}width",
        "line\u{2028}separator",
        "\u{FEFF}bom",
        "tag\u{E0041}",
    ];

    #[test]
    fn name_rules() {
        let v2 = |name| validate_name(name, NameRule::Version2);
        for good in [
            "report.pdf",
            "Ünïcødé name.txt",
            "a",
            "...",
            ".hidden",
            "a..b",
            "日本語のファイル.txt",
            "\u{1F4C4} notes",
            "x\u{2027}y",
            // Two flags in a row, and a flag at the end.
            "\u{1F3F4}\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F}\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}",
            // A plain black flag, with no tags.
            "\u{1F3F4}.png",
        ]
        .into_iter()
        .chain(JOINED_NAMES)
        {
            assert!(v2(good).is_ok(), "{good:?}");
            assert!(validate_name(good, NameRule::Version1).is_ok(), "{good:?}");
        }
        let too_long = "x".repeat(256);
        for (bad, rule) in [
            ("", "must be 1 to 255 bytes"),
            (too_long.as_str(), "must be 1 to 255 bytes"),
            ("line\nbreak", "must not contain control characters"),
            ("tab\there", "must not contain control characters"),
            ("del\u{7f}", "must not contain control characters"),
            ("a/b", "must not contain path separators"),
            ("a\\b", "must not contain path separators"),
            ("a\u{FF0F}b", "must not contain path separators"),
            ("a\u{FF3C}b", "must not contain path separators"),
            ("a\u{2215}b", "must not contain path separators"),
            ("a\u{2044}b", "must not contain path separators"),
            (".", "must not be . or .."),
            ("..", "must not be . or .."),
        ] {
            assert_eq!(v2(bad), Err(EnvelopeError::InvalidName(rule)), "{bad:?}");
        }
        // Every slash and backslash look-alike, such as `docs∖invoice.pdf`
        // shown as a path: refused by version 2, allowed by version 1.
        let look_alikes = [
            '\u{1735}',
            '\u{2044}',
            '\u{2215}',
            '\u{2216}',
            '\u{2571}',
            '\u{2572}',
            '\u{27CB}',
            '\u{27CD}',
            '\u{29F5}',
            '\u{29F8}',
            '\u{29F9}',
            '\u{2E4A}',
            '\u{FE68}',
            '\u{FF0F}',
            '\u{FF3C}',
            '\u{1F67C}',
            '\u{1F67D}',
        ];
        assert_eq!(look_alikes.len() + 2, PATH_SEPARATORS.len());
        for c in look_alikes {
            assert!(PATH_SEPARATORS.contains(&c), "{:04X}", u32::from(c));
            for name in [
                format!("docs{c}invoice.pdf"),
                format!("{c}"),
                format!("a{c}"),
            ] {
                assert_eq!(
                    validate_name(&name, NameRule::Version2),
                    Err(EnvelopeError::InvalidName(
                        "must not contain path separators"
                    )),
                    "{name:?}"
                );
                assert_eq!(validate_name(&name, NameRule::Version1), Ok(()), "{name:?}");
            }
        }
        let invisible = "must not contain invisible format or line separator characters";
        for bad in [
            // Shows as "invoiceexe.pdf".
            "invoice\u{202E}fdp.exe",
            "line\u{2028}separator",
            "paragraph\u{2029}separator",
            "zero\u{200B}width",
            "\u{200E}marked",
            "\u{200F}marked",
            "arabic\u{061C}mark",
            "\u{FEFF}bom",
            "isolate\u{2066}d\u{2069}",
            "word\u{2060}joiner",
            "\u{1343F}",
            "language\u{E0001}tag",
        ] {
            assert_eq!(
                v2(bad),
                Err(EnvelopeError::InvalidName(invisible)),
                "{bad:?}"
            );
        }
        let tags = "must not contain tag characters outside a flag";
        for bad in [
            // Hidden ASCII: "A".
            "tag\u{E0041}",
            "\u{E0067}\u{E0062}\u{E007F}",
            "a\u{E0067}\u{E0062}\u{E007F}",
            // No cancel tag, at the end or before more text.
            "\u{1F3F4}\u{E0067}\u{E0062}",
            "\u{1F3F4}\u{E0067}\u{E0062}.png",
            // A cancel tag alone, or right after the base.
            "a\u{E007F}",
            "\u{1F3F4}\u{E007F}",
            // Upper-case and punctuation tags spell no flag.
            "\u{1F3F4}\u{E0047}\u{E0042}\u{E007F}",
            "\u{1F3F4}\u{E0020}\u{E007F}",
            // Too long for a subdivision code: 8 tags.
            "\u{1F3F4}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E007F}",
            // A second run of tags after the first flag ends.
            "\u{1F3F4}\u{E0067}\u{E0062}\u{E007F}\u{E0067}\u{E007F}",
        ] {
            assert_eq!(v2(bad), Err(EnvelopeError::InvalidName(tags)), "{bad:?}");
        }
        // Seven tags is the longest code.
        assert!(v2(
            "\u{1F3F4}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E0061}\u{E007F}"
        )
        .is_ok());

        // Every format, line and paragraph separator character, as of
        // Unicode 16 (general categories Cf, Zl and Zp)...
        let format_or_separator = [
            (0x00AD, 0x00AD),
            (0x0600, 0x0605),
            (0x061C, 0x061C),
            (0x06DD, 0x06DD),
            (0x070F, 0x070F),
            (0x0890, 0x0891),
            (0x08E2, 0x08E2),
            (0x180E, 0x180E),
            (0x200B, 0x200F),
            (0x2028, 0x202E),
            (0x2060, 0x2064),
            (0x2066, 0x206F),
            (0xFEFF, 0xFEFF),
            (0xFFF9, 0xFFFB),
            (0x110BD, 0x110BD),
            (0x110CD, 0x110CD),
            (0x13430, 0x1343F),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0001, 0xE0001),
            (0xE0020, 0xE007F),
        ];
        // ...apart from the soft hyphen, the joiners and the tags.
        let allowed = [(0x00AD, 0x00AD), (0x200C, 0x200D), (0xE0020, 0xE007F)];
        let within = |ranges: &[(u32, u32)], c: char| {
            ranges
                .iter()
                .any(|&(first, last)| (first..=last).contains(&u32::from(c)))
        };
        let mut rejected = 0;
        for c in (0..=0x10_FFFF).filter_map(char::from_u32) {
            let forbidden = within(&format_or_separator, c) && !within(&allowed, c);
            assert_eq!(
                is_forbidden_format_character(c),
                forbidden,
                "{:04X}",
                u32::from(c)
            );
            rejected += usize::from(forbidden);
        }
        assert_eq!(rejected, 73);
    }

    #[test]
    fn version_1_names_follow_version_1_rules() {
        let map = data_map(&[100, 100, 98]);
        for name in VERSION_1_ONLY_NAMES.into_iter().chain(JOINED_NAMES) {
            let meta = metadata(Some("text/plain"), Some(name));
            assert_eq!(validate_name(name, NameRule::Version1), Ok(()), "{name:?}");
            assert_eq!(meta.validate_any_version(), Ok(()), "{name:?}");

            // A version 1 envelope with the name, as the first release
            // wrote it, still reads, byte for byte.
            let bytes = v1_bytes(&map, &meta);
            let parsed = Envelope::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.version(), ENVELOPE_VERSION_1);
            assert_eq!(parsed.metadata(), &meta);
            assert_eq!(parsed.to_bytes(), bytes, "{name:?}");
            assert_eq!(parsed.data_map(), Some(&map));

            // The same name in a version 2 envelope follows version 2's rule.
            let mut v2 = b"\0ANTLIST\x02\x3f".to_vec();
            put_field(&mut v2, Some("text/plain"));
            put_field(&mut v2, Some(name));
            v2.extend_from_slice(&encode_data_map(&map).unwrap());
            let new = Envelope::readable(&map, meta.clone(), ShownFields::ALL, true);
            if VERSION_1_ONLY_NAMES.contains(&name) {
                assert!(meta.validate().is_err(), "{name:?}");
                assert!(new.is_err(), "{name:?}");
                assert!(
                    matches!(
                        Envelope::from_bytes(&v2),
                        Err(EnvelopeError::InvalidName(_))
                    ),
                    "{name:?}"
                );
            } else {
                assert_eq!(new.unwrap().to_bytes(), v2, "{name:?}");
                assert_eq!(Envelope::from_bytes(&v2).unwrap().to_bytes(), v2);
            }
        }
        // Version 1's rule still refuses what it always did.
        for bad in ["a/b", "a\\b", "line\nbreak", "tab\there"] {
            let bytes = v1_bytes(&map, &metadata(None, Some(bad)));
            assert!(
                matches!(
                    Envelope::from_bytes(&bytes),
                    Err(EnvelopeError::InvalidName(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn new_uploads_follow_version_2_rules_whatever_their_version() {
        let map = data_map(&[100, 100, 98]);
        // A version 1 envelope written today, with a name version 2 forbids:
        // it parses, as stored ones must, but is no new upload.
        for name in VERSION_1_ONLY_NAMES {
            let bytes = v1_bytes(&map, &metadata(Some("text/plain"), Some(name)));
            let parsed = Envelope::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.version(), ENVELOPE_VERSION_1);
            assert!(
                matches!(
                    parsed.check_new_upload(),
                    Err(EnvelopeError::InvalidName(_))
                ),
                "{name:?}"
            );
        }
        // A version 1 envelope whose name both versions allow is still taken.
        for name in JOINED_NAMES.into_iter().chain(["report.pdf"]) {
            let bytes = v1_bytes(&map, &metadata(Some("text/plain"), Some(name)));
            let parsed = Envelope::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.check_new_upload(), Ok(()), "{name:?}");
        }
        assert_eq!(
            Envelope::from_bytes(&v1_bytes(&map, &Metadata::default()))
                .unwrap()
                .check_new_upload(),
            Ok(())
        );
        // Every version 2 envelope that parses is a valid new upload.
        for metadata in metadatas() {
            for withheld in [false, true] {
                let envelope = if withheld {
                    Envelope::withheld(&map, &SALT, metadata.clone(), ShownFields::NONE, true)
                } else {
                    Envelope::readable(&map, metadata.clone(), ShownFields::ALL, false)
                }
                .unwrap();
                let parsed = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
                assert_eq!(parsed.check_new_upload(), Ok(()));
            }
        }
    }

    #[test]
    fn rejects_invalid_metadata() {
        let map = data_map(&[1, 1, 1]);
        let map_bytes = rmp_serde::to_vec(&map).unwrap();
        for header in [
            &b"\0ANTLIST\x01"[..],
            b"\0ANTLIST\x02\x3f",
            b"\0ANTLIST\x02\x40",
        ] {
            let mut bytes = header.to_vec();
            bytes.extend_from_slice(b"\x03pdf\x00");
            bytes.extend_from_slice(&map_bytes);
            assert!(matches!(
                Envelope::from_bytes(&bytes),
                Err(EnvelopeError::InvalidContentType(_))
            ));
            let mut bytes = header.to_vec();
            bytes.extend_from_slice(b"\x00\x03a/b");
            bytes.extend_from_slice(&map_bytes);
            assert!(matches!(
                Envelope::from_bytes(&bytes),
                Err(EnvelopeError::InvalidName(_))
            ));
        }
        let bad = metadata(None, Some("a/b"));
        assert!(Envelope::readable(&map, bad.clone(), ShownFields::ALL, true).is_err());
        assert!(Envelope::withheld(&map, &SALT, bad, ShownFields::ALL, true).is_err());
    }
}
