//! Envelopes on uploads.
//!
//! An upload can store its data map, or for a private file a salted hash of
//! it, in an envelope ([`ant_listings::Envelope`]). The envelope's address is
//! the file's address, and its flags fix which of the five payment fields its
//! listing shows and whether the listing is in the index. Nodes that keep
//! listings record its payment when it is stored.
//!
//! The uploader's choices are an [`EnvelopeOptions`]. An upload needs an
//! envelope unless it is not in the index, hides all five payment fields and
//! has no metadata ([`EnvelopeOptions::needs_envelope`]); without one it is
//! stored exactly as an upload without listings support stores it. The
//! envelope is paid in the same payment as the content and stored after
//! every content chunk, so a listing never points at missing content.
//!
//! After the upload the client keeps an [`UploadEnvelope`]: the envelope, the
//! salt of a private one, and the record proving its payment
//! ([`ant_listings::EnvelopeProof`]), which the uploader can hand over to
//! prove the upload from the chain alone.

use super::file::Visibility;
use ant_listings::{
    Envelope, EnvelopeError, EnvelopeProof, Flags, Metadata, PaymentField, Salt, ShownFields,
};
use self_encryption::DataMap;
use std::fmt;

/// The uploader's choices for an upload: who can read it, whether it is in
/// the index, which payment fields anyone can see, and its metadata.
///
/// The three visibilities are names for three of the readable and index
/// combinations ([`EnvelopeOptions::private`], [`EnvelopeOptions::unlisted`],
/// [`EnvelopeOptions::listed`]); the fourth, in the index but not readable,
/// is a public, dated record of a file nobody can read until the uploader
/// reveals it. Every payment field is shown by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeOptions {
    /// Whether anyone with the address can read the file: the envelope
    /// carries the data map. Otherwise it carries a salted hash of it and the
    /// uploader keeps the data map and the salt.
    pub readable: bool,
    /// Whether the listing is in the index, so anyone can find the file.
    pub in_index: bool,
    /// The payment fields anyone can see.
    pub shown: ShownFields,
    /// Content type and name, stored in the envelope. Public and permanent,
    /// whatever the other choices.
    pub metadata: Metadata,
}

impl Default for EnvelopeOptions {
    fn default() -> Self {
        Self::private()
    }
}

impl EnvelopeOptions {
    /// Not readable, not in the index, every payment field shown.
    #[must_use]
    pub fn private() -> Self {
        Self {
            readable: false,
            in_index: false,
            shown: ShownFields::ALL,
            metadata: Metadata::default(),
        }
    }

    /// Readable by anyone with the address, not in the index, every payment
    /// field shown.
    #[must_use]
    pub fn unlisted() -> Self {
        Self {
            readable: true,
            ..Self::private()
        }
    }

    /// Readable and in the index, every payment field shown.
    #[must_use]
    pub fn listed() -> Self {
        Self {
            readable: true,
            in_index: true,
            ..Self::private()
        }
    }

    /// These options with `fields` hidden as well.
    #[must_use]
    pub fn hiding(mut self, fields: impl IntoIterator<Item = PaymentField>) -> Self {
        self.shown = fields
            .into_iter()
            .fold(self.shown, |shown, field| shown.without(field));
        self
    }

    /// These options with `metadata`.
    #[must_use]
    pub fn with_metadata(self, metadata: Metadata) -> Self {
        Self { metadata, ..self }
    }

    /// Whether the upload needs an envelope: unless it is not in the index,
    /// hides all five payment fields and has no metadata.
    #[must_use]
    pub fn needs_envelope(&self) -> bool {
        ant_listings::needs_envelope(&self.metadata, self.shown, self.in_index)
    }

    /// The envelope's flags.
    #[must_use]
    pub fn flags(&self) -> Flags {
        Flags {
            shown: self.shown,
            in_index: self.in_index,
            withheld: !self.readable,
        }
    }

    /// The visibility these options upload with: an envelope when one is
    /// needed, otherwise [`Visibility::Public`] (readable: a plain data map
    /// chunk) or [`Visibility::Private`] (nothing extra).
    #[must_use]
    pub fn into_visibility(self) -> Visibility {
        if self.needs_envelope() {
            Visibility::Envelope(self)
        } else if self.readable {
            Visibility::Public
        } else {
            Visibility::Private
        }
    }

    /// Check the metadata before anything is paid.
    ///
    /// # Errors
    ///
    /// Returns why the content type or name is not allowed.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        self.metadata.validate()
    }

    /// What these choices give away that the uploader may not expect.
    #[must_use]
    pub fn warnings(&self) -> Vec<EnvelopeWarning> {
        if !self.needs_envelope() {
            return Vec::new();
        }
        let shown = self.shown;
        let is_shown = |field| shown.contains(field);
        let mut warnings = Vec::new();
        for hidden in shown.hidden() {
            let full: Vec<PaymentField> = match hidden {
                PaymentField::BlockTimestamp => vec![
                    PaymentField::BlockNumber,
                    PaymentField::TxHash,
                    PaymentField::Quote,
                ],
                PaymentField::BlockNumber => vec![PaymentField::TxHash, PaymentField::Quote],
                PaymentField::TxHash => {
                    let mut by = Vec::new();
                    if is_shown(PaymentField::BlockNumber) && is_shown(PaymentField::LogIndex) {
                        by.extend([PaymentField::BlockNumber, PaymentField::LogIndex]);
                    }
                    by.push(PaymentField::Quote);
                    by
                }
                PaymentField::LogIndex => vec![PaymentField::Quote],
                PaymentField::Quote => Vec::new(),
            };
            let full: Vec<_> = full.into_iter().filter(|field| is_shown(*field)).collect();
            if !full.is_empty() {
                warnings.push(EnvelopeWarning::GivenAway {
                    hidden,
                    by: full,
                    extent: Extent::Fully,
                });
            } else if hidden == PaymentField::BlockNumber && is_shown(PaymentField::BlockTimestamp)
            {
                warnings.push(EnvelopeWarning::GivenAway {
                    hidden,
                    by: vec![PaymentField::BlockTimestamp],
                    extent: Extent::Roughly,
                });
            } else if hidden == PaymentField::TxHash
                && is_shown(PaymentField::BlockTimestamp)
                && is_shown(PaymentField::LogIndex)
            {
                // The timestamp gives the block roughly, and the few blocks
                // in that second hold few vault logs at the shown log index.
                warnings.push(EnvelopeWarning::GivenAway {
                    hidden,
                    by: vec![PaymentField::BlockTimestamp, PaymentField::LogIndex],
                    extent: Extent::Roughly,
                });
            } else if hidden == PaymentField::LogIndex && is_shown(PaymentField::TxHash) {
                // One of the transaction's vault logs, in quote-hash order
                // (`upload::order_by_quote_hash`): exact only if it has one.
                warnings.push(EnvelopeWarning::GivenAway {
                    hidden,
                    by: vec![PaymentField::TxHash],
                    extent: Extent::IfPaidAlone,
                });
            }
        }
        if is_shown(PaymentField::TxHash) && !is_shown(PaymentField::Quote) {
            warnings.push(EnvelopeWarning::TxHashWithoutQuote);
        }
        if !self.readable && !self.metadata.is_empty() {
            warnings.push(EnvelopeWarning::MetadataOnPrivate);
        }
        if shown != ShownFields::NONE {
            warnings.push(EnvelopeWarning::ShowsWallet { fields_shown: true });
        } else if self.in_index {
            warnings.push(EnvelopeWarning::ShowsWallet {
                fields_shown: false,
            });
        }
        warnings
    }

    /// Build the envelope for `data_map`. A private one needs `salt`: 32
    /// random bytes the uploader keeps.
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    pub(crate) fn envelope(
        &self,
        data_map: &DataMap,
        salt: Option<&Salt>,
    ) -> Result<Envelope, EnvelopeError> {
        match (self.readable, salt) {
            (true, _) => {
                Envelope::readable(data_map, self.metadata.clone(), self.shown, self.in_index)
            }
            (false, Some(salt)) => Envelope::withheld(
                data_map,
                salt,
                self.metadata.clone(),
                self.shown,
                self.in_index,
            ),
            (false, None) => Err(EnvelopeError::InvalidSaltedHash(0)),
        }
    }

    /// What identifies these choices apart from the salt, so an interrupted
    /// upload resumes with the same envelope.
    #[cfg(feature = "native")]
    pub(crate) fn scope(&self) -> Vec<u8> {
        let mut scope = vec![self.flags().to_byte()];
        scope.extend(rmp_serde::to_vec(&self.metadata).unwrap_or_default());
        scope
    }
}

/// The visibility of the library's upload shortcuts that take none:
/// `file_upload`, `file_upload_with_mode`, `file_upload_with_progress`,
/// `estimate_upload_cost`, `file_prepare_upload` and `data_prepare_upload`.
/// A private envelope with every payment field shown, as `darwin file upload`
/// stores by default ([`Visibility::default`]).
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn private_shortcut_visibility() -> Visibility {
    EnvelopeOptions::private().into_visibility()
}

/// The visibility of the library's public upload shortcuts,
/// `file_upload_public_with_mode` and `file_upload_public_with_progress`: the
/// unlisted envelope `darwin file upload --public` stores, readable by anyone
/// with its address, every payment field shown.
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn public_shortcut_visibility() -> Visibility {
    EnvelopeOptions::unlisted().into_visibility()
}

/// The payment fields a hide list leaves shown. Takes the names
/// [`PaymentField::name`] gives (`tx-hash`, `block`, `timestamp`,
/// `log-index`, `quote`) and `all`, so every client accepts the same words.
///
/// # Errors
///
/// Returns the first name that is none of these.
pub fn shown_after_hiding<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<ShownFields, String> {
    let mut shown = ShownFields::ALL;
    for name in names {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if name == "all" {
            shown = ShownFields::NONE;
            continue;
        }
        let field = PaymentField::from_name(name).ok_or_else(|| {
            format!(
                "unknown payment field {name:?}: use {}, or all",
                PaymentField::ALL.map(PaymentField::name).join(", ")
            )
        })?;
        shown = shown.without(field);
    }
    Ok(shown)
}

/// How much a shown field gives away of a hidden one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extent {
    /// Exactly.
    Fully,
    /// Roughly: a second holds only a few blocks.
    Roughly,
    /// Exactly, if the transaction paid for the envelope alone. Otherwise
    /// the envelope's log is one of the transaction's vault logs, told apart
    /// only by its quote: the client pays a transaction's quotes in
    /// quote-hash order, so the envelope is not always paid, and logged,
    /// last.
    IfPaidAlone,
}

/// Something an upload's choices give away that the uploader may not expect.
/// The choice stays the uploader's; a client shows these before uploading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeWarning {
    /// A hidden payment field can be worked out from shown ones.
    GivenAway {
        /// The hidden field.
        hidden: PaymentField,
        /// The shown fields that give it away.
        by: Vec<PaymentField>,
        /// How much they give away.
        extent: Extent,
    },
    /// The tx hash is shown without the quote: the wallet and time stay
    /// public, but nobody can check that the payment was for this file.
    TxHashWithoutQuote,
    /// The file is private but has metadata: anyone with the envelope's
    /// address, and the operators of the nodes storing it, can read the
    /// metadata, though not the file.
    MetadataOnPrivate,
    /// The paying wallet can be found: from the shown payment fields, or,
    /// with none shown, by matching when a listing in the index appeared
    /// against the vault's payments around then.
    ShowsWallet {
        /// Whether any payment field is shown.
        fields_shown: bool,
    },
}

fn field_text(field: PaymentField) -> &'static str {
    match field {
        PaymentField::TxHash => "tx hash",
        PaymentField::BlockNumber => "block number",
        PaymentField::BlockTimestamp => "block timestamp",
        PaymentField::LogIndex => "log index",
        PaymentField::Quote => "quote",
    }
}

fn what_it_gives(field: PaymentField) -> &'static str {
    match field {
        PaymentField::TxHash => "the transaction",
        PaymentField::BlockNumber => "the block",
        PaymentField::BlockTimestamp => "the time",
        PaymentField::LogIndex => "the log index",
        PaymentField::Quote => "the quote",
    }
}

impl fmt::Display for EnvelopeWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GivenAway { hidden, by, extent } => {
                let by: Vec<_> = by.iter().map(|field| field_text(*field)).collect();
                let verb = if by.len() == 1 { "is" } else { "are" };
                write!(
                    f,
                    "{} hidden, but {} {verb} shown, so {} is still public",
                    field_text(*hidden),
                    by.join(" and "),
                    what_it_gives(*hidden),
                )?;
                match extent {
                    Extent::Fully => Ok(()),
                    Extent::Roughly => f.write_str(", roughly (a second holds only a few blocks)"),
                    Extent::IfPaidAlone => {
                        f.write_str(" if the transaction paid for the envelope alone")
                    }
                }
            }
            Self::TxHashWithoutQuote => f.write_str(
                "tx hash shown without the quote: the wallet and time stay public, \
                 but nobody can check that the payment was for this file",
            ),
            Self::MetadataOnPrivate => f.write_str(
                "the name and content type of this private file are readable by anyone \
                 with the envelope's address, and by the operators of the nodes storing it, \
                 though the file is not",
            ),
            Self::ShowsWallet { fields_shown: true } => f.write_str(
                "the payment fields shown give away the paying wallet to anyone \
                 with the envelope's address",
            ),
            Self::ShowsWallet {
                fields_shown: false,
            } => f.write_str(
                "a listing in the index shows roughly when it was paid, which can be matched \
                 against the vault's payments to find the paying wallet",
            ),
        }
    }
}

/// The envelope stored with an upload, and what the uploader keeps of it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UploadEnvelope {
    /// The envelope, as stored.
    pub envelope: Envelope,
    /// The salt of a private envelope's salted hash. Keep it with the data
    /// map: revealing both proves which file the envelope is for.
    pub salt: Option<Salt>,
    /// The record proving the envelope's payment: the envelope, its
    /// payment's tx hash and paid quote, and for a private envelope the data
    /// map and salt. `None` when this upload didn't pay for the envelope
    /// (`proof_problem` says why).
    pub proof: Option<EnvelopeProof>,
    /// Whether `proof` was checked against the chain. It is built from the
    /// payment proof sent to the nodes either way; `proof_problem` says why a
    /// check didn't happen or failed.
    pub proof_checked: bool,
    /// Why there is no proof, or why it wasn't checked.
    pub proof_problem: Option<String>,
}

impl UploadEnvelope {
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    pub(crate) fn new(envelope: Envelope, salt: Option<Salt>) -> Self {
        Self {
            envelope,
            salt,
            proof: None,
            proof_checked: false,
            proof_problem: None,
        }
    }

    /// The envelope's address: the file's address.
    #[must_use]
    pub fn address(&self) -> [u8; 32] {
        self.envelope.address()
    }

    /// Whether anyone with the address can read the file.
    #[must_use]
    pub fn readable(&self) -> bool {
        !self.envelope.is_withheld()
    }
}

/// What the payment proof sent with an envelope's PUT says about its payment.
#[cfg(feature = "native")]
struct ProvenPayment {
    /// Every quote in the proof.
    quotes: Vec<ant_protocol::evm::PaymentQuote>,
    /// The transactions that paid them.
    tx_hashes: Vec<[u8; 32]>,
    /// The quote with a non-zero amount under the single-node rule (the
    /// median, paid three times its price).
    paid: ant_protocol::evm::PaymentQuote,
}

/// Read the paid quote and its transaction from the payment proof sent with
/// an envelope's PUT.
#[cfg(feature = "native")]
fn paid_quote(proof_bytes: &[u8]) -> Result<ProvenPayment, String> {
    let (proof, tx_hashes) = ant_protocol::payment::deserialize_proof(proof_bytes)?;
    let quotes: Vec<_> = proof
        .peer_quotes
        .into_iter()
        .map(|(_, quote)| quote)
        .collect();
    let plan = super::batch::SingleNodeQuotePayment::from_quotes(quotes.clone())
        .map_err(|e| e.to_string())?;
    let paid: Vec<_> = plan
        .quotes
        .iter()
        .filter(|info| !info.amount.is_zero())
        .collect();
    let [paid] = paid.as_slice() else {
        return Err(format!("{} quotes paid, expected one", paid.len()));
    };
    let quote = quotes
        .iter()
        .find(|quote| quote.hash() == paid.quote_hash)
        .cloned()
        .ok_or("the paid quote is not in the proof")?;
    let tx_hashes = tx_hashes.into_iter().map(|tx| tx.0).collect();
    Ok(ProvenPayment {
        quotes,
        tx_hashes,
        paid: quote,
    })
}

/// Why a record isn't checked when the client has no EVM network.
#[cfg(feature = "native")]
const NO_EVM_NETWORK: &str = "no EVM network configured (with_evm_network or with_wallet)";

#[cfg(feature = "native")]
impl super::Client {
    /// Fill in `envelope`'s proof record from the payment proof sent with its
    /// PUT (`proof_bytes`; `None` if this upload didn't pay for it), checked
    /// on `network`'s chain ([`complete_upload_envelope`]). Without a network
    /// the record is built unchecked. Never fails: the upload is paid and
    /// stored by now.
    pub(crate) async fn complete_upload_envelope(
        &self,
        envelope: &mut UploadEnvelope,
        data_map: &DataMap,
        proof_bytes: Option<&[u8]>,
        network: Option<&ant_protocol::evm::Network>,
    ) {
        let chain = network
            .ok_or_else(|| NO_EVM_NETWORK.to_string())
            .and_then(|network| {
                super::listings::ListingChain::new(network).map_err(|e| e.to_string())
            });
        match chain {
            Ok(chain) => {
                complete_upload_envelope(envelope, data_map, proof_bytes, Some(&chain)).await;
            }
            Err(e) => {
                complete_upload_envelope(envelope, data_map, proof_bytes, None).await;
                if envelope.proof.is_some() {
                    envelope.proof_problem = Some(format!("not checked against the chain: {e}"));
                }
            }
        }
    }

    /// Fill in `envelope`'s record from `record`, the one an earlier upload
    /// of the same envelope by the same payer kept, checked on `network`'s
    /// chain ([`reuse_upload_record`]). Never fails.
    pub(crate) async fn reuse_upload_record(
        &self,
        envelope: &mut UploadEnvelope,
        record: EnvelopeProof,
        network: &ant_protocol::evm::Network,
    ) {
        match super::listings::ListingChain::new(network) {
            Ok(chain) => reuse_upload_record(envelope, record, Some(&chain)).await,
            Err(e) => {
                reuse_upload_record(envelope, record, None).await;
                envelope.proof_problem = Some(format!("not checked against the chain: {e}"));
            }
        }
    }

    /// Note on an external-signer upload's envelope, before anything is
    /// paid, that its record won't be checked against the chain when the
    /// client has no EVM network. The upload still works: finalize builds the
    /// record from the payment proof alone.
    pub(crate) fn note_unchecked_envelope(&self, envelope: &mut UploadEnvelope) {
        if self.require_evm_network().is_err() {
            tracing::warn!(
                "The envelope's record will not be checked against the chain: {NO_EVM_NETWORK}"
            );
            envelope.proof_problem = Some(format!(
                "the record will not be checked against the chain: {NO_EVM_NETWORK}"
            ));
        }
    }
}

/// Fill in `envelope`'s proof record from the payment proof sent with its PUT
/// (`proof_bytes`; `None` if this upload didn't pay for it), the way the
/// nodes find the payment: from the uploader's own receipt on `chain`, then
/// checked with [`ant_listings::check_proof`]. If the chain can't be read (or
/// `chain` is `None`), the record is built from the payment proof alone and
/// marked unchecked: its paid quote is the one the single-node rule pays.
#[cfg(feature = "native")]
pub(crate) async fn complete_upload_envelope(
    envelope: &mut UploadEnvelope,
    data_map: &DataMap,
    proof_bytes: Option<&[u8]>,
    chain: Option<&super::listings::ListingChain>,
) {
    let Some(proof_bytes) = proof_bytes else {
        envelope.proof_problem = Some(
            "this upload didn't pay for the envelope: it was already stored, \
             so its payment record belongs to an earlier upload"
                .into(),
        );
        return;
    };
    let salt = envelope.salt;
    let reveal = |record: EnvelopeProof| -> Result<EnvelopeProof, String> {
        match salt {
            Some(salt) => {
                let bytes = ant_listings::encode_data_map(data_map).map_err(|e| e.to_string())?;
                record.with_reveal(bytes, salt).map_err(|e| e.to_string())
            }
            None => Ok(record),
        }
    };
    let ProvenPayment {
        quotes,
        tx_hashes,
        paid: quote,
    } = match paid_quote(proof_bytes) {
        Ok(paid) => paid,
        Err(problem) => {
            envelope.proof_problem = Some(format!("unreadable payment proof: {problem}"));
            return;
        }
    };
    let local = tx_hashes
        .first()
        .ok_or_else(|| "the payment proof has no transaction".to_string())
        .and_then(|tx| {
            EnvelopeProof::new(&envelope.envelope, *tx, &quote).map_err(|e| e.to_string())
        })
        .and_then(reveal);
    let local = match local {
        Ok(record) => record,
        Err(problem) => {
            envelope.proof_problem = Some(format!("cannot build the proof record: {problem}"));
            return;
        }
    };
    let Some(chain) = chain else {
        envelope.proof = Some(local);
        envelope.proof_problem = Some("not checked against the chain".into());
        return;
    };
    let address = envelope.envelope.address();
    let mut problem = "the payment transaction is not on chain yet".to_string();
    for tx in &tx_hashes {
        let (receipt, timestamp) = match chain.transaction(tx).await {
            Ok(Some(found)) => found,
            Ok(None) => continue,
            Err(e) => {
                problem = e;
                break;
            }
        };
        let checked =
            ant_listings::find_payment(&address, &quotes, &receipt, timestamp, chain.vault())
                .map_err(|e| e.to_string())
                .and_then(|payment| {
                    EnvelopeProof::from_payment(&envelope.envelope, &payment)
                        .map_err(|e| e.to_string())
                })
                .and_then(reveal)
                .and_then(|record| {
                    ant_listings::check_proof(&record, &receipt, timestamp, chain.vault())
                        .map(|_| record)
                        .map_err(|e| e.to_string())
                });
        match checked {
            Ok(record) => {
                envelope.proof = Some(record);
                envelope.proof_checked = true;
                envelope.proof_problem = None;
                return;
            }
            Err(e) => problem = e,
        }
    }
    envelope.proof = Some(local);
    envelope.proof_problem = Some(format!("not checked against the chain: {problem}"));
}

/// Fill in `envelope`'s record from `record`, the one an earlier upload of
/// the same envelope by the same payer kept until its caller saved it: this
/// upload found the envelope already stored, so it paid nothing for it, but
/// the earlier payment was this payer's. Checked on `chain` when given.
#[cfg(feature = "native")]
pub(crate) async fn reuse_upload_record(
    envelope: &mut UploadEnvelope,
    record: EnvelopeProof,
    chain: Option<&super::listings::ListingChain>,
) {
    envelope.proof_problem = match chain {
        Some(chain) => chain
            .check_proof(&record)
            .await
            .err()
            .map(|problem| format!("not checked against the chain: {problem}")),
        None => Some("not checked against the chain".into()),
    };
    envelope.proof_checked = envelope.proof_problem.is_none();
    envelope.proof = Some(record);
}

/// The data map a record or proof gives, checked against its envelope: the
/// envelope's own, or the revealed one of a private envelope. Doesn't check
/// the payment ([`ListingChain::check_proof`](super::listings::ListingChain::check_proof)
/// does).
///
/// # Errors
///
/// Returns why: the envelope doesn't parse or hash to the proof's address,
/// the reveal doesn't match, or a private envelope's data map isn't revealed.
pub fn proof_data_map(proof: &EnvelopeProof) -> Result<DataMap, String> {
    let envelope = Envelope::from_bytes(&proof.envelope).map_err(|e| format!("envelope: {e}"))?;
    if envelope.address() != proof.address {
        return Err("the envelope does not hash to the proof's address".into());
    }
    if let Some(map) = envelope.data_map() {
        return Ok(map.clone());
    }
    match (&proof.data_map, &proof.salt) {
        (Some(bytes), Some(salt)) => envelope
            .check_reveal(bytes, salt)
            .map_err(|e| format!("reveal: {e}")),
        _ => Err("the file is private and this proof doesn't reveal its data map".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_map() -> DataMap {
        let (map, _) = self_encryption::encrypt(bytes::Bytes::from(vec![7u8; 4000])).unwrap();
        map
    }

    fn metadata() -> Metadata {
        Metadata {
            content_type: Some("text/plain".into()),
            name: Some("notes.txt".into()),
        }
    }

    /// The library's upload shortcuts store an envelope: the private one
    /// `darwin file upload` stores by default, and for the public ones the
    /// unlisted one `--public` stores. Neither stores a bare data map or no
    /// envelope at all.
    #[test]
    fn upload_shortcuts_store_envelopes_with_every_field_shown() {
        assert_eq!(private_shortcut_visibility(), Visibility::default());
        let Visibility::Envelope(private) = private_shortcut_visibility() else {
            panic!("the private shortcuts store an envelope");
        };
        assert_eq!(private, EnvelopeOptions::private());
        assert!(!private.readable && !private.in_index);
        let Visibility::Envelope(public) = public_shortcut_visibility() else {
            panic!("the public shortcuts store an envelope");
        };
        assert_eq!(public, EnvelopeOptions::unlisted());
        assert!(public.readable && !public.in_index);
        for options in [private, public] {
            assert_eq!(options.shown, ShownFields::ALL);
            assert!(options.metadata.is_empty());
            assert!(options.needs_envelope());
        }
    }

    #[test]
    fn the_shorthands_map_to_the_readable_and_index_choices() {
        let cases = [
            (EnvelopeOptions::private(), false, false),
            (EnvelopeOptions::unlisted(), true, false),
            (EnvelopeOptions::listed(), true, true),
        ];
        for (options, readable, in_index) in cases {
            assert_eq!(options.readable, readable);
            assert_eq!(options.in_index, in_index);
            assert_eq!(options.shown, ShownFields::ALL);
            assert!(options.metadata.is_empty());
        }
        assert_eq!(EnvelopeOptions::default(), EnvelopeOptions::private());
        // An upload that names no visibility stores the private envelope,
        // every payment field shown.
        assert_eq!(
            Visibility::default(),
            Visibility::Envelope(EnvelopeOptions::private())
        );
        // The flag bytes the format examples give.
        assert_eq!(EnvelopeOptions::listed().flags().to_byte(), 0x3f);
        assert_eq!(EnvelopeOptions::unlisted().flags().to_byte(), 0x1f);
        assert_eq!(EnvelopeOptions::private().flags().to_byte(), 0x5f);
        let dated = EnvelopeOptions {
            in_index: true,
            ..EnvelopeOptions::private()
        };
        assert_eq!(dated.flags().to_byte(), 0x7f);
        let hidden = EnvelopeOptions::private().hiding(PaymentField::ALL);
        assert_eq!(hidden.flags().to_byte(), 0x40);
    }

    #[test]
    fn an_envelope_is_needed_unless_unindexed_all_hidden_and_without_metadata() {
        for shown in ShownFields::every() {
            for in_index in [false, true] {
                for readable in [false, true] {
                    for metadata in [Metadata::default(), metadata()] {
                        let options = EnvelopeOptions {
                            readable,
                            in_index,
                            shown,
                            metadata: metadata.clone(),
                        };
                        let needed = in_index || shown != ShownFields::NONE || !metadata.is_empty();
                        assert_eq!(options.needs_envelope(), needed);
                        let visibility = options.clone().into_visibility();
                        match (needed, readable) {
                            (true, _) => assert_eq!(visibility, Visibility::Envelope(options)),
                            (false, true) => assert_eq!(visibility, Visibility::Public),
                            (false, false) => assert_eq!(visibility, Visibility::Private),
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn hide_lists_take_the_field_names_and_all() {
        assert_eq!(shown_after_hiding([]).unwrap(), ShownFields::ALL);
        assert_eq!(shown_after_hiding(["all"]).unwrap(), ShownFields::NONE);
        assert_eq!(
            shown_after_hiding(["tx-hash", " quote "]).unwrap(),
            ShownFields::ALL
                .without(PaymentField::TxHash)
                .without(PaymentField::Quote)
        );
        for field in PaymentField::ALL {
            assert_eq!(
                shown_after_hiding([field.name()]).unwrap(),
                ShownFields::ALL.without(field)
            );
        }
        assert!(shown_after_hiding(["block-number"]).is_err());
        assert!(shown_after_hiding(["Quote"]).is_err());
    }

    fn given_away(options: &EnvelopeOptions) -> Vec<(PaymentField, Vec<PaymentField>, Extent)> {
        options
            .warnings()
            .into_iter()
            .filter_map(|warning| match warning {
                EnvelopeWarning::GivenAway { hidden, by, extent } => Some((hidden, by, extent)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn hidden_fields_given_away_by_shown_ones_are_reported() {
        use PaymentField::*;
        let only = |shown: &[PaymentField], hidden: PaymentField| {
            let options = EnvelopeOptions {
                shown: shown.iter().copied().collect(),
                ..EnvelopeOptions::private()
            };
            given_away(&options)
                .into_iter()
                .find(|(field, _, _)| *field == hidden)
                .map(|(_, by, extent)| (by, extent))
        };
        // The plan's table, one row at a time.
        assert_eq!(
            only(&[BlockNumber], BlockTimestamp),
            Some((vec![BlockNumber], Extent::Fully))
        );
        assert_eq!(
            only(&[TxHash], BlockTimestamp),
            Some((vec![TxHash], Extent::Fully))
        );
        assert_eq!(
            only(&[Quote], BlockTimestamp),
            Some((vec![Quote], Extent::Fully))
        );
        assert_eq!(
            only(&[TxHash], BlockNumber),
            Some((vec![TxHash], Extent::Fully))
        );
        assert_eq!(
            only(&[Quote], BlockNumber),
            Some((vec![Quote], Extent::Fully))
        );
        assert_eq!(
            only(&[BlockTimestamp], BlockNumber),
            Some((vec![BlockTimestamp], Extent::Roughly))
        );
        assert_eq!(
            only(&[BlockNumber, LogIndex], TxHash),
            Some((vec![BlockNumber, LogIndex], Extent::Fully))
        );
        assert_eq!(only(&[BlockNumber], TxHash), None);
        assert_eq!(only(&[LogIndex], TxHash), None);
        // The timestamp gives the block roughly, and with the log index the
        // transaction too.
        assert_eq!(
            only(&[BlockTimestamp, LogIndex], TxHash),
            Some((vec![BlockTimestamp, LogIndex], Extent::Roughly))
        );
        assert_eq!(only(&[BlockTimestamp], TxHash), None);
        assert_eq!(
            only(&[BlockNumber, BlockTimestamp, LogIndex], TxHash),
            Some((vec![BlockNumber, LogIndex], Extent::Fully))
        );
        let hide_tx_block_quote = EnvelopeOptions {
            shown: [BlockTimestamp, LogIndex].into_iter().collect(),
            ..EnvelopeOptions::private()
        };
        let warned: Vec<String> = hide_tx_block_quote
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(warned.contains(
            &"tx hash hidden, but block timestamp and log index are shown, so the transaction \
              is still public, roughly (a second holds only a few blocks)"
                .to_string()
        ));
        assert!(warned.contains(
            &"block number hidden, but block timestamp is shown, so the block is still public, \
              roughly (a second holds only a few blocks)"
                .to_string()
        ));
        assert_eq!(only(&[Quote], TxHash), Some((vec![Quote], Extent::Fully)));
        // The envelope is paid in quote-hash order with the content
        // (`upload::order_by_quote_hash`, tested there), so the tx hash gives
        // its log index away only when it paid for the envelope alone.
        assert_eq!(
            only(&[TxHash], LogIndex),
            Some((vec![TxHash], Extent::IfPaidAlone))
        );
        assert_eq!(
            EnvelopeWarning::GivenAway {
                hidden: LogIndex,
                by: vec![TxHash],
                extent: Extent::IfPaidAlone
            }
            .to_string(),
            "log index hidden, but tx hash is shown, so the log index is still public \
             if the transaction paid for the envelope alone"
        );
        assert_eq!(only(&[Quote], LogIndex), Some((vec![Quote], Extent::Fully)));
        // Nothing gives the quote away, and nothing shown gives nothing away.
        for shown in ShownFields::every() {
            let options = EnvelopeOptions {
                shown,
                ..EnvelopeOptions::private()
            };
            for (hidden, by, _) in given_away(&options) {
                assert_ne!(hidden, Quote);
                assert!(!shown.contains(hidden));
                assert!(by.iter().all(|field| shown.contains(*field)));
            }
        }
        assert!(given_away(&EnvelopeOptions::private()).is_empty());
        assert_eq!(
            only(&[BlockNumber], BlockTimestamp).map(|(by, extent)| EnvelopeWarning::GivenAway {
                hidden: BlockTimestamp,
                by,
                extent
            }
            .to_string()),
            Some(
                "block timestamp hidden, but block number is shown, so the time is still public"
                    .into()
            )
        );
    }

    #[test]
    fn the_other_warnings_follow_the_choices() {
        let has = |options: &EnvelopeOptions, wanted: &EnvelopeWarning| {
            options.warnings().contains(wanted)
        };
        let tx_only = EnvelopeOptions {
            shown: [PaymentField::TxHash].into_iter().collect(),
            ..EnvelopeOptions::unlisted()
        };
        assert!(has(&tx_only, &EnvelopeWarning::TxHashWithoutQuote));
        assert!(!has(
            &EnvelopeOptions::unlisted(),
            &EnvelopeWarning::TxHashWithoutQuote
        ));

        let private_named = EnvelopeOptions::private().with_metadata(metadata());
        assert!(has(&private_named, &EnvelopeWarning::MetadataOnPrivate));
        let unlisted_named = EnvelopeOptions::unlisted().with_metadata(metadata());
        assert!(!has(&unlisted_named, &EnvelopeWarning::MetadataOnPrivate));
        let hidden_named = EnvelopeOptions::private()
            .hiding(PaymentField::ALL)
            .with_metadata(metadata());
        assert!(has(&hidden_named, &EnvelopeWarning::MetadataOnPrivate));

        let wallet = EnvelopeWarning::ShowsWallet { fields_shown: true };
        assert!(has(&EnvelopeOptions::private(), &wallet));
        let listed_hidden = EnvelopeOptions::listed().hiding(PaymentField::ALL);
        assert!(has(
            &listed_hidden,
            &EnvelopeWarning::ShowsWallet {
                fields_shown: false
            }
        ));
        assert!(!has(&listed_hidden, &wallet));
        // Without an envelope there is nothing to warn about.
        assert!(EnvelopeOptions::private()
            .hiding(PaymentField::ALL)
            .warnings()
            .is_empty());
        for warning in EnvelopeOptions::listed()
            .hiding([PaymentField::Quote])
            .with_metadata(metadata())
            .warnings()
        {
            assert!(!warning.to_string().is_empty());
        }
    }

    #[test]
    fn envelopes_follow_the_choices() {
        let map = data_map();
        let salt = [5u8; 32];
        for readable in [false, true] {
            for in_index in [false, true] {
                let options = EnvelopeOptions {
                    readable,
                    in_index,
                    shown: ShownFields::ALL.without(PaymentField::LogIndex),
                    metadata: metadata(),
                };
                let envelope = options.envelope(&map, Some(&salt)).unwrap();
                assert_eq!(envelope.version(), 2);
                assert_eq!(envelope.flags(), options.flags());
                assert_eq!(envelope.metadata(), &metadata());
                if readable {
                    assert!(envelope.data_map() == Some(&map));
                } else {
                    assert!(envelope.data_map().is_none());
                    let bytes = ant_listings::encode_data_map(&map).unwrap();
                    assert!(envelope.check_reveal(&bytes, &salt).unwrap() == map);
                    assert!(envelope.check_reveal(&bytes, &[6; 32]).is_err());
                    // A private envelope needs its salt.
                    assert!(options.envelope(&map, None).is_err());
                }
            }
        }
        // The scope ignores the salt but not the choices.
        let private = EnvelopeOptions::private();
        assert_eq!(private.scope(), EnvelopeOptions::private().scope());
        assert_ne!(private.scope(), EnvelopeOptions::unlisted().scope());
        assert_ne!(
            private.scope(),
            EnvelopeOptions::private().with_metadata(metadata()).scope()
        );
    }

    #[test]
    fn bad_metadata_is_refused_before_paying() {
        let options = EnvelopeOptions::listed().with_metadata(Metadata {
            content_type: None,
            name: Some("a/b".into()),
        });
        assert!(options.validate().is_err());
        assert!(EnvelopeOptions::listed()
            .with_metadata(metadata())
            .validate()
            .is_ok());
    }

    /// A private envelope for `map`, paid in one transaction with two other
    /// chunks, as the upload engine's proof bytes give it: three quotes, the
    /// median one paid.
    struct PaidEnvelope {
        upload: UploadEnvelope,
        proof_bytes: Vec<u8>,
        paid: ant_protocol::evm::PaymentQuote,
        tx_hash: [u8; 32],
    }

    fn paid_envelope(map: &DataMap, options: &EnvelopeOptions) -> PaidEnvelope {
        use super::super::listings::test_chain::signed_quote;
        use ant_protocol::evm::EncodedPeerId;
        use ant_protocol::payment::{serialize_single_node_proof, PaymentProof};
        let salt = (!options.readable).then_some([0x5a; 32]);
        let envelope = options.envelope(map, salt.as_ref()).unwrap();
        let quotes: Vec<_> = [10, 20, 30]
            .into_iter()
            .map(|price| signed_quote(envelope.address(), price))
            .collect();
        let tx_hash = [0xab; 32];
        let proof = PaymentProof {
            proof_of_payment: ant_protocol::evm::ProofOfPayment {
                peer_quotes: quotes
                    .iter()
                    .map(|quote| {
                        (
                            EncodedPeerId::new(*blake3::hash(&quote.pub_key).as_bytes()),
                            quote.clone(),
                        )
                    })
                    .collect(),
            },
            tx_hashes: vec![ant_protocol::evm::TxHash::from(tx_hash)],
            commitment_sidecars: Vec::new(),
        };
        PaidEnvelope {
            upload: UploadEnvelope::new(envelope, salt),
            proof_bytes: serialize_single_node_proof(&proof).unwrap(),
            paid: quotes[1].clone(),
            tx_hash,
        }
    }

    fn receipt(paid: &PaidEnvelope) -> ant_listings::PaymentReceipt {
        use super::super::listings::test_chain::{paying_log, signed_quote};
        ant_listings::PaymentReceipt {
            tx_hash: paid.tx_hash,
            success: true,
            block_number: 120,
            logs: vec![
                paying_log(&signed_quote([1; 32], 20), 0),
                paying_log(&paid.paid, 1),
                paying_log(&signed_quote([2; 32], 20), 2),
            ],
        }
    }

    #[tokio::test]
    async fn the_record_is_the_envelope_its_paid_quote_and_the_reveal() {
        use super::super::listings::test_chain::{reader, serve, MockChain};
        let map = data_map();
        for options in [
            EnvelopeOptions::private().with_metadata(metadata()),
            EnvelopeOptions::listed(),
        ] {
            let mut paid = paid_envelope(&map, &options);
            let mut chain = MockChain::with_blocks(200, 1_800_000_000);
            chain.add_receipt(receipt(&paid));
            let chain = reader(serve(std::sync::Arc::new(std::sync::Mutex::new(chain))).await);
            complete_upload_envelope(
                &mut paid.upload,
                &map,
                Some(&paid.proof_bytes),
                Some(&chain),
            )
            .await;
            assert!(paid.upload.proof_checked, "{:?}", paid.upload.proof_problem);
            assert_eq!(paid.upload.proof_problem, None);
            let record = paid.upload.proof.clone().expect("record");
            assert_eq!(record.address, paid.upload.address());
            assert_eq!(record.tx_hash, paid.tx_hash);
            // The paid quote, not another chunk's or an unpaid one.
            let quote: ant_protocol::evm::PaymentQuote =
                rmp_serde::from_slice(&record.quote).unwrap();
            assert_eq!(quote.hash(), paid.paid.hash());
            assert_eq!(record.salt.is_some(), !options.readable);
            assert!(proof_data_map(&record).unwrap() == map);

            // Anyone can check it from the chain alone.
            let proven = chain.check_proof(&record).await.unwrap();
            assert_eq!(proven.payment.block_number, 120);
            assert_eq!(proven.payment.log_index, 1);
            assert_eq!(proven.payment.block_timestamp, 1_800_000_240);
            assert!(proven.data_map.as_ref() == Some(&map));

            // A record that reads back from its text checks the same.
            let text = record.to_hex().unwrap();
            let read = EnvelopeProof::from_hex(&text).unwrap();
            assert!(chain.check_proof(&read).await.is_ok());

            if !options.readable {
                // Proving the payment without revealing the file.
                let mut hidden = record.clone();
                hidden.data_map = None;
                hidden.salt = None;
                let proven = chain.check_proof(&hidden).await.unwrap();
                assert!(proven.data_map.is_none());
                assert!(proof_data_map(&hidden).is_err());
                // A wrong salt fails.
                let mut wrong = record.clone();
                wrong.salt = Some([0x5b; 32]);
                assert!(chain.check_proof(&wrong).await.is_err());
                assert!(proof_data_map(&wrong).is_err());
            }
            // Tampering with the payment fails.
            let mut tampered = record.clone();
            tampered.tx_hash = [0xac; 32];
            assert!(chain.check_proof(&tampered).await.is_err());
            let mut tampered = record.clone();
            tampered.envelope[9] ^= 0x01;
            assert!(chain.check_proof(&tampered).await.is_err());
            assert!(proof_data_map(&tampered).is_err());
        }
    }

    #[tokio::test]
    async fn without_the_chain_the_record_is_built_unchecked() {
        let map = data_map();
        let mut paid = paid_envelope(&map, &EnvelopeOptions::private());
        complete_upload_envelope(&mut paid.upload, &map, Some(&paid.proof_bytes), None).await;
        assert!(!paid.upload.proof_checked);
        assert!(paid.upload.proof_problem.is_some());
        let record = paid.upload.proof.clone().expect("record");
        let quote: ant_protocol::evm::PaymentQuote = rmp_serde::from_slice(&record.quote).unwrap();
        assert_eq!(quote.hash(), paid.paid.hash());
        assert!(proof_data_map(&record).unwrap() == map);
        // It still checks out once the chain can be read.
        let receipt = receipt(&paid);
        let proven = ant_listings::check_proof(
            &record,
            &receipt,
            1_800_000_240,
            &super::super::listings::test_chain::VAULT,
        )
        .unwrap();
        assert_eq!(proven.payment.log_index, 1);

        // An unreachable chain: the same.
        let unreachable = super::super::listings::test_chain::reader("http://127.0.0.1:9".into());
        let mut paid = paid_envelope(&map, &EnvelopeOptions::unlisted());
        complete_upload_envelope(
            &mut paid.upload,
            &map,
            Some(&paid.proof_bytes),
            Some(&unreachable),
        )
        .await;
        assert!(!paid.upload.proof_checked);
        assert!(paid.upload.proof.is_some());
        assert!(paid
            .upload
            .proof_problem
            .as_deref()
            .is_some_and(|problem| problem.starts_with("not checked against the chain")));
    }

    #[tokio::test]
    async fn a_kept_record_is_reused_and_checked_again() {
        use super::super::listings::test_chain::{reader, serve, MockChain};
        let map = data_map();
        let mut paid = paid_envelope(&map, &EnvelopeOptions::unlisted());
        let mut chain = MockChain::with_blocks(200, 1_800_000_000);
        chain.add_receipt(receipt(&paid));
        let chain = reader(serve(std::sync::Arc::new(std::sync::Mutex::new(chain))).await);
        complete_upload_envelope(
            &mut paid.upload,
            &map,
            Some(&paid.proof_bytes),
            Some(&chain),
        )
        .await;
        let record = paid.upload.proof.clone().expect("record");

        // A later upload of the same envelope found it stored and paid
        // nothing: the earlier upload's kept record is its record.
        let fresh = || UploadEnvelope::new(paid.upload.envelope.clone(), None);
        let mut again = fresh();
        reuse_upload_record(&mut again, record.clone(), Some(&chain)).await;
        assert!(again.proof_checked, "{:?}", again.proof_problem);
        assert_eq!(again.proof_problem, None);
        assert_eq!(again.proof, Some(record.clone()));

        // Without a chain it is used unchecked.
        let mut again = fresh();
        reuse_upload_record(&mut again, record.clone(), None).await;
        assert!(!again.proof_checked);
        assert_eq!(again.proof, Some(record.clone()));
        assert_eq!(
            again.proof_problem.as_deref(),
            Some("not checked against the chain")
        );

        // One that doesn't check out is kept, and says why.
        let mut tampered = record;
        tampered.tx_hash = [0xac; 32];
        let mut again = fresh();
        reuse_upload_record(&mut again, tampered, Some(&chain)).await;
        assert!(!again.proof_checked);
        assert!(again
            .proof_problem
            .as_deref()
            .is_some_and(|problem| problem.starts_with("not checked against the chain: ")));
    }

    #[tokio::test]
    async fn an_envelope_this_upload_did_not_pay_for_has_no_record() {
        let map = data_map();
        let mut paid = paid_envelope(&map, &EnvelopeOptions::unlisted());
        complete_upload_envelope(&mut paid.upload, &map, None, None).await;
        assert!(paid.upload.proof.is_none());
        assert!(paid
            .upload
            .proof_problem
            .as_deref()
            .is_some_and(|problem| problem.contains("already stored")));
        let mut paid = paid_envelope(&map, &EnvelopeOptions::unlisted());
        complete_upload_envelope(&mut paid.upload, &map, Some(b"garbage"), None).await;
        assert!(paid.upload.proof.is_none());
        assert!(paid.upload.proof_problem.is_some());
    }
}
