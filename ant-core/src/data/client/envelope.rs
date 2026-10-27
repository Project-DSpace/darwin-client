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
            ant_listings::find_payment(&address, &quotes, &receipt, timestamp, chain.vaults())
                .map_err(|e| e.to_string())
                .and_then(|payment| {
                    EnvelopeProof::from_payment(&envelope.envelope, &payment)
                        .map_err(|e| e.to_string())
                })
                .and_then(reveal)
                .and_then(|record| {
                    ant_listings::check_proof(&record, &receipt, timestamp, chain.vaults())
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

    /// The envelope's paid quote is the one the single-node rule pays, read
    /// from the proof, which carries no amounts: the median quote whether
    /// the plan paid the full or the weighted amount. So the record of an
    /// upload resumed across the pricing switch names the quote either
    /// client paid.
    #[cfg(feature = "native")]
    #[test]
    fn the_envelopes_paid_quote_is_the_median_at_either_amount() {
        use crate::data::client::upload_state::test_state::{plan_priced, weighted};
        use ant_protocol::evm::{Amount, TxHash};
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let full = plan_priced(&[5u8; 3000], now, &[10_000_000, 30_000_000, 20_000_000]);
        let weighted = weighted(full.clone());
        assert_ne!(full.payment.total_amount(), weighted.payment.total_amount());
        let paid = |plan: &super::super::batch::ChunkPaymentPlan| {
            let transactions = plan
                .payment
                .quotes
                .iter()
                .filter(|quote| !quote.amount.is_zero())
                .map(|quote| (quote.quote_hash, TxHash::from([7; 32])))
                .collect();
            let proof = super::super::batch::build_plan_proof(plan, &transactions).unwrap();
            paid_quote(&proof).unwrap().paid.hash()
        };
        let median = full
            .peer_quotes
            .iter()
            .find(|(_, quote)| quote.price == Amount::from(20_000_000u64))
            .map(|(_, quote)| quote.hash())
            .unwrap();
        assert_eq!(paid(&full), median);
        assert_eq!(paid(&weighted), median);
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
            &ant_listings::VaultSet::v2_only(super::super::listings::test_chain::VAULT),
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

    /// The listings format's golden values: the same literals darwin-node
    /// pins (src/listings/golden.rs), generated once from darwin-listings
    /// v0.2.1 (381d7c1) under its own Cargo.lock (rmp-serde 1.3.1,
    /// `self_encryption` 0.36.0, postcard 1.1.3). They are literals, never
    /// computed at test time, so a change in this lock's encoders shows.
    mod golden {
        use ant_listings::Metadata;
        use self_encryption::{ChunkInfo, DataMap, XorName};

        fn infos() -> Vec<ChunkInfo> {
            [
                (0x11, 0x21, 4_000),
                (0x12, 0x22, 4_000),
                (0x13, 0x23, 3_999),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (dst, src, src_size))| ChunkInfo {
                index,
                dst_hash: XorName([dst; 32]),
                src_hash: XorName([src; 32]),
                src_size,
            })
            .collect()
        }

        /// The file's data map: three chunks, 11,999 bytes.
        pub fn data_map() -> DataMap {
            DataMap::new(infos())
        }

        /// The same chunks as a child map, as a shrunk data map is stored.
        pub fn child_map() -> DataMap {
            DataMap::with_child(infos(), 1)
        }

        /// The envelopes' metadata.
        pub fn metadata() -> Metadata {
            Metadata {
                content_type: Some("text/plain".to_string()),
                name: Some("notes.txt".to_string()),
            }
        }

        /// The salt of the private envelope.
        pub const SALT: [u8; 32] = [3; 32];

        /// `encode_data_map(&data_map())`, hex.
        pub const DATA_MAP: &str = "9301939400dc00201111111111111111111111111111111111111111111111111111111111111111dc00202121212121212121212121212121212121212121212121212121212121212121cd0fa09401dc00201212121212121212121212121212121212121212121212121212121212121212dc00202222222222222222222222222222222222222222222222222222222222222222cd0fa09402dc00201313131313131313131313131313131313131313131313131313131313131313dc00202323232323232323232323232323232323232323232323232323232323232323cd0f9fc0";

        /// `encode_data_map(&child_map())`, hex.
        pub const CHILD_MAP: &str = "9301939400dc00201111111111111111111111111111111111111111111111111111111111111111dc00202121212121212121212121212121212121212121212121212121212121212121cd0fa09401dc00201212121212121212121212121212121212121212121212121212121212121212dc00202222222222222222222222222222222222222222222222222222222222222222cd0fa09402dc00201313131313131313131313131313131313131313131313131313131313131313dc00202323232323232323232323232323232323232323232323232323232323232323cd0f9f01";

        /// `salted_hash(&SALT, DATA_MAP)`, hex: what the private envelope carries.
        pub const SALTED_HASH: &str =
            "2ab61dabaca72a3eaf12dfc1061b0f3309a612f21019e0e62db97bedc8171ed8";

        /// The private envelope, hex.
        pub const PRIVATE_ENVELOPE: &str = "00414e544c495354025f0a746578742f706c61696e096e6f7465732e7478742ab61dabaca72a3eaf12dfc1061b0f3309a612f21019e0e62db97bedc8171ed8";

        /// Its address, hex.
        pub const PRIVATE_ADDRESS: &str =
            "1caad8d4d502ecdbe32032fd674b6092b83c9b6caa2c0e43fa93c82d81826191";

        /// The unlisted envelope, hex.
        pub const UNLISTED_ENVELOPE: &str = "00414e544c495354021f0a746578742f706c61696e096e6f7465732e7478749301939400dc00201111111111111111111111111111111111111111111111111111111111111111dc00202121212121212121212121212121212121212121212121212121212121212121cd0fa09401dc00201212121212121212121212121212121212121212121212121212121212121212dc00202222222222222222222222222222222222222222222222222222222222222222cd0fa09402dc00201313131313131313131313131313131313131313131313131313131313131313dc00202323232323232323232323232323232323232323232323232323232323232323cd0f9fc0";

        /// Its address, hex.
        pub const UNLISTED_ADDRESS: &str =
            "d994f77c1e68e705416e63ef3f830225f1b19d1236e8729768f8b5d70ab7130a";

        /// The listed envelope, hex.
        pub const LISTED_ENVELOPE: &str = "00414e544c495354023f0a746578742f706c61696e096e6f7465732e7478749301939400dc00201111111111111111111111111111111111111111111111111111111111111111dc00202121212121212121212121212121212121212121212121212121212121212121cd0fa09401dc00201212121212121212121212121212121212121212121212121212121212121212dc00202222222222222222222222222222222222222222222222222222222222222222cd0fa09402dc00201313131313131313131313131313131313131313131313131313131313131313dc00202323232323232323232323232323232323232323232323232323232323232323cd0f9fc0";

        /// Its address, hex.
        pub const LISTED_ADDRESS: &str =
            "29f14ad2b6037dbc576c7c1a2ade9ace807262bac6cbe1c7bbf9422ff3e62121";

        /// The transaction [`PRIVATE_RECORD`] names.
        pub const PRIVATE_RECORD_TX: [u8; 32] = [0x5a; 32];

        /// The private upload's `.record`, without its final newline.
        pub const PRIVATE_RECORD: &str = "011caad8d4d502ecdbe32032fd674b6092b83c9b6caa2c0e43fa93c82d818261913f00414e544c495354025f0a746578742f706c61696e096e6f7465732e7478742ab61dabaca72a3eaf12dfc1061b0f3309a612f21019e0e62db97bedc8171ed85a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5ad43e98dc00201cccaaccd8ccd4ccd502ccecccdbcce32032ccfd674b60cc92ccb83ccc9b6cccaa2c0e43ccfacc93ccc82dcc81cc8261cc9192ce6ab13b8000c42000000000000000000000000000000000000000000000000001bc16d674ec8000c414ababababababababababababababababababababdc07a0cc86cc934ccc873accec55ccc0ccf0311832ccdaccbf41746bccc66b6d1e481fcceacce307ccf7ccee7c5ecce2ccaa6435cceecc9dcce1cc9677ccd62026cc9e36476d23ccc1487810cc99ccb21420cca815cca3ccf5cce0123b0c2c4c7b45cca8ccefccd3ccc274ccbd70ccaa07ccee460113cc9e7f6fccab09ccb611cceaccb0cc8a7e7048cc8e67cc97cc9f2dccf4cceecc86cc96ccee212e1accbdccd2cce716ccc2ccad00ccd13dccd4cc942e28ccc3ccc3ccde3c27552eccfe293b2e7dccfc58ccd57827ccbb043443cca17448cc9d76cca7ccf87a492602cccbcce55955ccae3b35ccfbccca45ccfe53155718cca4cc9fccef19ccc9ccdecc9ccca918cce177cce4721d32ccb7cc90ccec57cce3cca5cc9b0c3c14284861cc8bccbfcc97ccf01454cca6cca25a703ecc91060b02cc9753103a0079ccc6ccea611eccfacc89134d14ccf1cc89ccaf7fccf6676accb968ccd0ccf571ccfeccd7ccfaccb0cc86ccb9ccfb0f6357cca7ccd5027d7f30cca9cc99cc96ccda50ccd54b342c09cc9cccc742cc80cc82cccc15cce2cca2555accbc4a6c296750087cccf36e44ccf3ccac527150cce00b2d773dcca4cccd1b68ccc5ccbecc8a0c6eccb0ccd06e6863cceacc8a4e576fcceb0c48cca6292219cca56dccc8cceeccc7ccc222ccf7ccfbcc8bcc9b0f6dcccd52cce9cc88ccd8cc9ccc9bccb73cccaecc99cc84ccaecca7ccb14dccd4cca146117613cc97cc8fcc912ecc8e6d1c05cc9535cc8bccd73238ccf43756ccbccc9a58cccccce9ccd8ccdfccbbccdcccb237cce64246ccfecca144ccf82569ccd62acc85cca87bccb2787319ccdacccfcc856fcc9a20cca9150a79ccf1cccdccfcccf2cc9009cc8bcce268cc854d03ccf2ccf52f1ecc86001f7f1a05cce27f5c210fcce9191ccc8474cc91ccf82cccac04cc9bcce4cccd151d2c7acc820202cca9ccbfccd7ccb4ccf4ccdc72cc8b5acca1ccc663ccb5cc9725ccbd4fcc83ccb4ccc9ccb7cccc211eccc36cccecccdc2ecc8fccd66847ccfecc9002cc9e4a1a4eccb9cca12414ccfa1fccdb5b47ccccccee33655040ccd2ccb05ecc8ccc9c523642ccf4cc9e6b54cce56accd7ccd149cc8566ccf3ccebccd204ccd40c4d68ccda48cca9ccefcca3ccfdccfe1429cc8acc89ccc37374cce2322a4dccb1493b0d0110ccfc0accdb7acc8a6955001eccb5ccae63ccbe5c3a57ccae5eccda78cc92cce9ccce3f07cc834a0ccc87cce2cc9bcca8cce84dcca5ccf906567b0ccc82ccda49ccc9cc974a0908cce014ccbcccfcccfd18ccf8ccebcc9accb653cc825ecca32f44ccaf5c5c2dccba487ecca8ccc8ccc56bccd9ccd946cc92ccdf1509ccc4cc991fcc9f65ccabcc85cceacc91cce5ccf5cca6ccef45ccae060accc1ccee3dccafccf5ccd20a29ccba26ccaa0224cc8e4accb2ccf74e5e52695105cca1ccf6cce800ccd10529cccecc9340ccb62dccaf77ccf967062665cca1ccae71ccbdcc89006accfcccf8ccc574ccf1cc89cc8876573244ccbf3bccdacc972c57cc9dccaeccac606572414eccd3cce50dccf0ccfa33cc9accceccd8cce6cc9050ccc7607eccf6cccfcca7cccc3356cc9513cccaccb1ccafcce6cca1ccccccee5f0accf91f50cca65fccd5ccdeccf3ccd86127cca9ccfa2eccd734cc90ccaaccd847cc82ccdb0a4c1d4718464bccebccb6cc81ccd5ccd372ccc667070c291bcc83cce62d3b66ccea77cce0cce222ccea3f186ecceb6d10ccebcc81cc883cccd1cceacc95ccc764ccd1ccd0cce74e70ccf229cc9c004b16cc811bccbecc8acce205ccb542ccf54acc924e2b0b53cce2ccde61cc9fccaa0854cc844fccfa38294ccc8bcc9a2607cce1ccf3cc9accc16eccc4ccb8ccd8ccd92f3fcc80ccbe15ccee3e316bccdacc8acca677cc846749cc9a7eccb818cccbccb1cc837767ccafccd572424e68cce87177cc8339ccda207f49ccf0cce149cc86cca6cc8d14cc9e5b6cccc3ccab10cc8054ccd4ccc3ccfacc904accb91accb956cc86ccd5cce9ccbc1ecc8bccb6cc97ccbaccda3fccb30e711dcccdcc801d647bcce2ccb1ccf2cc9b712dccc62e5461ccd4cc94cc92ccd1cce717cca1757d5c68067312cc8d33cca9ccafccdf2620ccf5ccf9ccaaccfa08cca5385050ccd4cca7ccbccc9acc8f08cce91cccf463cce75a52cccd2dcca8ccc5446d50cceacc98ccc555ccf12848cc9fccf5cc80ccef5502ccb6ccb4cccfccb2ccddccd470cccaccd3ccf1ccc0cc9160cc8bccedcc8209cce768ccd8ccef632204ccf6ccbb69ccca621235ccbc0124cccf6a25ccca4accaccce453cc9cccfa3d0dcceb557d4a6dcc971b56cceecce90dcca00a2ecc80ccb5ccb42471cc9746ccfa5acc9a09ccfccc8573ccf47870ccf42ecca8ccd33d14ccf75fccdbcc9031ccbbcc94cccbccc6cce915cca837ccaaccdacccacc81cc8eccf26213ccc95335cc8cccbbcc99ccd2553a2319ccca0735ccaecc8ecc92093dccc8062bccddcc92cc89cccb31ccdd2e0ccce9cca05ccca5ccc1ccccccfdccc423cc9cccf82f2c6bcccf1cccadcccb5518ccaf2acc805d45cccdccea6fcc8376cc951274ccbacc9e37cca6700c7654ccdb0c25ccadccf5ccea3fcc9f06ccbe542f2408cca476cce7ccf2cc92cc99ccbc7cccf82b6accc5cc8c5fcccc21cc9430293b49ccf02accbfcca4ccc319ccd1ccac4e0b76ccd1ccc546cca9027a190979ccaf4eccceccc24374cce6ccbdccf174720d0273150fccf9cc9dcc8d72cca10dccdd070fcc89cca156cccccc9e67364ccce40573cc85ccf1ccefccc9ccc7ccee4c73340d0acc9227465bccc1ccc4305429ccc2ccf253ccff07714cccd6ccac3ecce6ccd4ccacccc6ccdc7f3eccf24cccbaccb7cccc7fccf12bcce7cc803fccf2cc94ccf9ccb4cccacca41dccd8cce5cccbcc82cc9fcccbcc9b442f31446701ccb4ccd1ccc5ccea1f29ccf2236e35cca629086ecceeccd3ccd1cc85ccb8ccb4456acc8fcc8f69ccaa724accef6fcc9bccb049637acca3007b0e45ccce0ccc8d27183b1765cceeccbcccde0ecce3ccaeccb6cccacc8071ccf7cc89645e166bcccbcceccca2ccf70dcce31e0d656fcc97cce2ccf7566bcccbcc84037458364ecc94ccd9784016ccffccc204273f3e6402365accf764cc97ccf81bcca37d42360fcc8bccff7605cc9fcc97ccc2ccf8ccf435472a2f4acce2131ecccf3e5eccb6ccb0ccfa51ccd561cc914dcc9f3ccce8ccd5ccd3ccad13261bccc96b51ccb85137ccda43cc96cce0cccf3268cca3ccc0ccf351cc9e0639ccc62b3bcc99cc9f31ccbaccabcce9cc97cca649ccf2cce7cc9e4a421207ccadccd0241414187d16150d4214ccce5a136f7b5dccfcccda29ccfccc87cc9f78ccf7cceb726458ccd70471ccacccf546cca317ccd558cca4cce1ccdf5dcce83826207cccf2cce2ccfacc96ccd3cc9bccaccc8227ccc1cca3ccf9cca4ccec68127c037967ccd9cce9cca562cca6cca415cc82213acc9cccfd7a7dcce9575844cc830417cc862accc9726bccabccf859ccdd14cc9e4976ccc8cce7ccee13cca7ccdf14cc9accef44cc96cc8e56ccedcca4cca57accca2dcc8f0a7eccf0cce9ccf3cc98ccb8cccd6bcc98ccdd173ecce0ccdcccb92544750f7d5c4464ccf0cc8721cce8ccfa363f71cca3382917ccbdccdfccf5cc9e5dcc99767bccaecca95dccd0ccef55ccd0721060cc9dcccd42cc94ccc425ccb5ccdc11cce030611bccbf6fcc8745cca47814026858401fcce805792bcccb376ccc8d7fccd33d0fcca2ccddccbe6a36ccbfccb91758ccbaccec29cc8bccc6614b6ccc941b712050cc93cc87cc93ccd1ccd8cccecccaccb9cc8e4ccc8375cc9f6ecc934ccc86cce412ccb9ccd1cc86ccf2ccef357dccf67e6600cccb7d05cce4ccd9067d4cccae24cccfccd0cc88094a12ccf35f0b4d7d33ccf7cc89ccaacce4ccf8cc9d6231354fcc8fccb6ccbf00ccf54fccf746192fccb708ccf40accef7d1dccd5cca1ccafccb9092d2acce06dccef18cced225fcc8a4d2fcceeccb1ccc8cca067cca315ccf61651ccb3ccdbcca217ccecccc0ccbbcc88ccde06ccea546a3f44ccdeccfdccc3cccbccb57b32ccf839ccac2accd1ccbe78cc90ccab16ccc1ccaacc87ccd9ccf74a0a6357746112dc0ced531b62cce2cce02865ccce66cce5ccce233273ccdd42cce31237ccc516cc9ecce3cce617737dcc9dcc83ccef0635ccca6dcc9dccbdccefccb7ccef38cce9ccd9ccf6cc83cc8d564dccf5cc940929ccc2cce2ccd9cc8d6bcc8e40ccd4ccf827762b3cccd731cce85fcc930f463954cced3fcce6cc9f50ccb05fccf91b5ecce80c76cce2ccc62accdfcccb71cc823417cc8acca0ccf0cca9291139ccb715cce00fcc94ccca10cca513ccfcccb41e77ccb96a366accacccab320fccde39ccbc7fccbfcc92cc88cce923ccc3ccb1ccefcc9873ccc9cc9ecc8352cc96cccf0dcc84cca71173cce8cccacc9ecc97cc87cce653ccd4070e7250cc92cce20e1477262007110bccc6ccaf4f29ccc60d3c064f1eccc1cc8811ccd5ccd4ccbe3accafcc8039ccd64132ccf21c0327ccd6cce9ccdfccc90eccc368cc9d260777cc874b6979ccd939cc8ecce4cccfcc842868ccf6ccd568620b4c24637dcc8f0a29ccbdccf1232acceacc8ecccfcccb12cc910acc9d78cc9329cccccc844dccee5ecc9845ccffccfe05ccfc630dcc88cc92ccd2cc87cc96077dccb1422bccfdccabcca1ccd76b33cc91cc8f1dcc9a0ccc95ccea5bccdacc81ccbd15ccc9cc85cce6cc91cc84ccc5ccd20213ccd429ccc8ccfdccd910464a16ccf2ccc1ccc74dcc96cca17ccc96cc810074ccb6cc8cccee0364ccb3cca7cc9acce371015e372a315dccbc253623ccb33655012fcc871dccdfcc9fccf1ccdbccafccf7483dcc95167fcc9a01664b44476d6a351fccc6ccbf5c16ccc8173707ccfcccb5ccc2cca9ccafcc9f2ecca3ccb7ccfa406c3a3accdfccc53ecc927314740a3ecce0ccc62c70ccef5c1f25cc88cce8ccc3cc9ecc925accb85a62ccb2cca023ccf7cc9accf7cc95ccf3cc85ccfd326c622f6a07ccd920cc83cc9ecc8acca4cc8accf2ccb3455eccfe0131ccc229ccf4cc9a652dccc4ccd467ccfc2d72cce047ccf5243421cc9dccea4ecc8d7bcce1cc9acce7ccdcccce1413ccdbcc8767cc9705ccfb0a0bccd6cc84ccb5ccf4cce671cc966018ccb2ccb8ccb2ccabccc03f6a5647ccd346cccdccd80849ccfbccb92ccc9d5e74ccadcc81cc867812ccbb630300ccb43e3acc9cccc07e1bccef38ccceccbd0acc9accfb0c087fcccccc8fccac2acc90cc98ccb8cc96cce368012cccda3dcc9ccc9d7f5915cccacc95cc96cca8ccdd2c1eccc0ccb5ccbacc8d03ccd259cccaccc9ccbbccb5ccc1ccbe2f63ccf577cce0cc87cc9acccbccf7ccdf252d1fcc94232022cce71eccfa17ccf6cc8fccf4cce1ccfe49cc923eccc96d11ccf32ecce91dccf9ccb0ccde2b57cc8c56cca906cc9116cc82cce578ccee6ecc83ccc1cca8ccbc35471d414ccc98ccee7acc80cccdccda69ccac03ccc7293bccc6cccecce0cc99cccc222dcc8eccb6cc9d62cca924cc8accdccc90cca5ccedccb0ccf03d6904cc97cc8e3e321fccc2360638cc9e7063cc990cccd129ccc1511a0a77ccb6ccafccffccf950cc81ccdf45cc94463338cc9226ccbf6c006d3bccf87e53ccacccd7cce11ecc8621cced19ccf11d67cc81ccf5ccc76f77ccb63427ccddccea5176ccd417ccacccca3a0cccfc36ccdeccf1ccf9ccbaccc1cc9519cc96cc84cc93ccee3a774c5933ccbdcc97cca1ccb72e0eccedccd8ccf53a08190dccf0ccd3cce0ccd363ccbd3159ccf22a24ccb2ccccccd732ccf82a356d7637cce7620eccc32b7555ccf456ccf37900ccc766cca923cce32c73726bccf01b55210621cc9fccbdcc971fccd2ccbfccdacc8eccd3cc9552ccf2ccf30bcc8179ccbd15ccc5ccc511ccc7cced5dccd3cce7ccce0263ccb3ccb413ccb11e7dcce6ccf8ccf0cc96cc98ccd8181a3b03cca0cc8a27ccaaccddcc91ccb0ccf60403ccd8cce64bcccf6360ccc1140336cc987b79ccaa1accd31ccc8ecc9bccb015cc91ccbfccdacc90cccb5bcce3cc9f4acca7cc96cce0cc9ecca3cc90cca953cca46fcc87ccf92accc6cc91ccf0ccd2ccb9437bccc35dccbeccdacca3cc941dccb3cce350ccacccec4d63cccd5324cca7cc811274ccf4cc8bcca1ccf62f3eccd80fcc9cccdaccf3ccec511d7c76cc9bccf463ccee393a35191d450f52cc9dcca5ccdd0f3b7b7b77000b63ccc9ccd50cccbbcce564cccaccfdcca4ccf6033bcca861cca7cc88580cccafccac0b16cc9bcce937ccb7cca941ccf0ccac5a20ccbd5c2025cc8211ccf2ccaacc8d2417ccd2ccf9ccda26555267cca611cc8fcca5cc887eccf1375f63cca248cc9e12cce43accec2c5d7fcc8e0d37cce936ccb11727cc87482bccdaccdd01cce038ccc93ccca30b1801ccb1ccf9ccd6ccbb31574170ccb5424025031672683f29cce7ccbb4114ccd3505d0dccd92fcc9067120dccf33940587a25ccf9cc857dccb9ccd954cc8cccd13510633dcc82ccfa22ccf6cc90ccbaccf83a60ccbcccb95c5b633bccb95b4eccc1ccaa55ccbb52cce6197fcca22e005b7b766532723bcc8b7bcc882268cc8e177901461821cce9ccc827cca34c2207cc8205cceccca5074dccc7cc8f58683348ccb84bccf74c7bcca72accef0dccab4053cc871a45ccd262cca559ccd9cccd02551075ccfc26cce6ccab2acc8649ccedcce60b454673ccc72d5822790e66ccaacc963fccb33a22cc9ecc9d4d51cc9b7842cca77bccb507302cccf765cca3cc9fcce0cc89ccda49542a54cc87ccc46138cccd5a280d403a17ccb669cc8accee5c4acc82cc8d1a1809cccb697accbf1fccdf1accec4eccdb35ccaaccd6ccfc05ccafccc35a04cca4483a6200ccaecc8943ccabcceb2b2446cccd7f31cc93cc9ccca77accd7cced1663cca3ccbacc8accffccec6716ccf54d6dcceaccc2ccfa5eccba0bcca1ccfb4bcce3cc9d61cccb7631ccfecce3cce6ccd2ccf6cc8f4951ccdecc8646cca465ccb54474ccb33bccf8ccc8cccaccbc597fccdc58cca1ccba322d3accc4ccd4ccffcc8fcc9ccc85ccae38464a5accb7cc84ccb4cccc39cca226cca15548ccb3ccfeccff0dccb4416ecc8130ccbc62ccccccd96c54ccecccf811ccb9ccdacccb053215184544306230ccb5440bcccc09cce83acc8f5c7e26252accd33761ccadccd22d7dcce8cc910accf1ccb05730ccc648ccb9cc9eccbe73cccaccfd34cca7ccb1ccc0cceb40ccd2ccb3ccabccc8ccf84eccbe79ccc91d1eccd25bcce36fcc9137293fccd01502ccccccf3ccb2ccd0cc8fcccf4eccffcc8c720eccdeccfc4733ccf70dcccd56ccd64b6d691715cc9bccf24cccbe65ccc1154e37cc92ccbbcca0ccd2cca06340cc98ccf42b78ccc50acca707541d5408cc94cccaccb7cc92ccc66020ccbd293fccfccc8fcce1cc96cc9fcc9cccc5ccf732ccd9ccdf06ccab0fccc4ccd8ccbeccec7fcc8652304d14ccfaccfcccccccad1bccafccc5cc9010144113ccb9cc9540ccf5ccc0cc9110ccfaccdd24230c32ccff24ccff11cced6c05246d1945ccebccffccf479ccefccc5cccbccc9395553ccb5cc9bccecccb4cca16547cca5ccb6ccde1f24ccf81d4dccd61714cc99cc8d1fccdacca5ccef1c3e05ccf2cc9accde62ccae243c02ccbbccce56cc92cc9f0b4070ccbd5309cc9b7ccc90372c3b30ccc2ccdfcced3231171f35ccd02bcce07fcce6cccbcc90ccd6cce3ccc113ccb6ccfbccb619ccdf7f7d24ccfc1bcc8e34ccc7397455ccbccccd5ccccdcc845a1bcce3cce708cce1ccae27cc94036531ccd64644cca4cca1ccc5ccc824cccfccef22ccd6ccd5356d1bccdb42ccb920ccb516cc8bccc1ccd5ccd32739cce336cc973b30cca9ccb94036cc81cc82cc820611726d28ccf0ccc1cce0cca41d6a05060d11ccbbcce41e15ccea5dccba2845cca10c59cc96ccd501cc88ccc1cc9173ccfe6a19ccfd25cca9014f09cca1ccd5cca9cc89ccc817ccf4ccd565374e1c0e35422647cc8b0124ccc67d53ccb63a762630722b70cce8cca35809ccde240ccccccc80767f164b4b0143cc8c4b4d2a41442c6d1cccdbccf96609cca4654d7713ccffcce9cc9f637ecc943677cca4ccd8cc92ccdeccfccc81cc8accdfccab54cca4ccce21cce4ccd9ccc5ccbeccccccc5cc9524ccd3ccbbccad09ccd6ccd7cca572ccb062cccbccea75cca8cc93ccb16c14ccbe6cccd9cc8632cc90cce644cccf26cca00accb870ccc224ccdf24753934ccd1cc8c7e5cccefcca5cce670cca307ccbcccfdccb422cc80cc82ccc2cc8959ccbaccc4cc9a3fcc9eccad7977cceb3169cc9ccc9c54ccfd17652a75ccd1361c36ccf63524cc9fccdacc8038ccc477ccf41e62cce0cc88cce93dccd8cc85791b5d10ccb76127cca919100fcce62918ccf954cc8fccfc182ccca253ccffccaacccd5a64ccd8083e64162acce0ccb5cc8fccffcc89ccccccafcccbcce7cc9324cce1ccb16dcc8bccc7ccea7b30cc9a77ccafcca1cca253ccc32026ccf0ccd652cceccceacca95dccca4423ccdecce06bcc98cc9ecccaccc179ccd7ccc5ccdc5b290f3e29ccf25d06ccf30f7461210eccb65703ccd26717ccd2ccfecce7ccbd5bccf105ccc03accaeccc9ccd758ccaecce5ccba282f2ecca25accb34fccb50950ccff5fccb0cce677ccb11a56cced12ccaacc832e4fccf2cce6ccd35d19ccf73862ccedccfbcca5cccbccf0cc950341cceb65cc980d5ccc82ccdd5f36ccb2ccfccce8cce5ccadccfdccfbcccc7cccd7cc81ccf7cc97ccea366716ccbb1230ccb1ccd063ccc8cc9d662411cca3ccc1713c1009ccb6ccfecc89ccd572cc86cce9cccccce8ccc6ccf071ccaacc946963cccf3e5accd6ccc5cc8a442d03cce510284553ccc56821cc80ccb1ccfa3b3fccda62ccfecccfcccccce6ccea24337ecca2ccd366ccbaccd0cc8f674551ccbccc8a28ccec07ccb002ccdf3606cce8ccff5331ccb8cce14432cca31c4675cca54fcce21a11407b52ccde1a19ccdc5bccd6ccd27ccc8323072accebcccd5bcccecce831ccf44b51ccfa765373cced73ccbeccdd75ccb5ccdacce1124408cca61814ccc8ccd8ccdc4154575b5752ccb037ccae2b4bcca3797dccec01cca85dccb9ccdd51cc92ccb14dcc96ccd72852ccca06cc877cccceccaf676bccf8cce4cc8e60ccba557c51ccaccccb41cc90ccb21e0415253c3d0bcca9cca437ccffcce8626d48ccd0cc90ccc66f0f57ccb3cca6cc91ccbd1254ccf272002bccddccc878cc8c2bcccf080b2943ccbaccf3ccd3ccaf033c2817ccd44ccc8accbaccce5b2eccccccbe0c20ccabcc824f2fcca2584dcccb4d1dcca077ccc7ccc8ccd5ccb421cca053ccb834451d70ccaaccb4cc9bccc5cc8b2d40cc830a2fccf2cc9477190fccc6cc8f1b26ccd7cce9ccb0ccc254ccbd22ccb510ccbaccffcc82ccb547ccd64110ccb128ccd2cc8539ccb5ccbc78ccf80c0b55cca36dccfecce35b1fcc90ccd07b5c184f0eccb857ccc860706dcc8174cc9043ccbaccdeccf95f3bcc99ccad5eccc22102cc88ccceccda6b50706478cca8ccf2791c43cc97ccb56cccfb475bcccfcc85ccab60cced5fcce02dcc94ccd9ccca2b6e77ccc7ccc0ccf7cca550ccb34a6eccf1ccda1a7ccc9632cc9d081fccdfccca42ccd1cc9d3104ccd131ccf15d6dcc9a42796a26ccef016accddcc8b0b4d3ecccccc87ccba26ccd6ccafccc478ccd91f03ccd9ccc42c363cccdc4eccaa1c3f36ccfdccf05ecccdccc936ccc73266347ccce6ccb8cc990265ccd03a010d1ccc85ccab42ccfb5e7cccfd2eccf632ccef1accf5ccfa4accd64f6d71ccf8ccc0287acc90ccccccfbccf8cc9dccdf460b40ccc3ccbeccd6cce14bccb9425974ccb0ccde454dcc971d27cc96ccacccb4ccb95511240f344bccb4ccfbcc9161ccbbccab5eccdf236acce7cc905fccf549780c5a2eccc4ccb8ccec06cc85ccc9cca7ccb6ccedcc89667acca1cc9d20cc8cccc4ccb1cc83cc9bccafccd17e3dccd6ccd536cc8b2356ccb67c68cc9f6476cceaccc7ccc0cccbcc94ccd9cce90724cc981ecc8a3f466462ccb73216cc9dcc85ccfcccc9095e19ccf8cce77dccbf27ccdb20cc91250f711d02cc8dcc95cceaccbbccba294f3c71cce32141ccd64cccffccd2cce71fccdf32352accc518cca1ccf6cc8077cce257ccdeccaacc8e13cca575cc9dccdbcc9251cc9c7dcc8bcca81b623bcc82cca5742c67ccb62a1fcc9dccf83dcc954d3c2a06ccc714cc8f1555ccbfcce3cce301ccfc0dcc9bcc9959cc900e1acc8eccc307cce9142cccb847ccbe38cc9dcca4cc996625044640ccd5ccd0cce7ccd0551e02cc8dccb8cca029ccf734cce2cc97cc9f1eccc446ccfecc96ccd46c394cccda6442062f45cce07accedcc9319cceacc8321cceccc9e15ccf9ccb22341cce4ccf663ccb1cc88763f23ccc3ccebcceecc98484cccb1334cccbb2374657accd5cc90ccfbcc887accaecc930b05cce2cca87170437350cccbcccf48ccaccce752ccef583e0b4122004d5816cce3cc80283dcc971c2dccefccc4ccb76eccddccce70464b49ccf7cca908ccbbccf7ccbacc834a4e79013f4eccdfccac412204ccf3cca3ccfc045f017736397cccdb456236ccaf5b5454cc9d222127cc9cccba7bcc97cc8cccd61a7cccd3cce734ccc305cc931c7209cccb6023ccd43f1ccc83cca8cc8b04307bcc9478ccfd54620ecce1ccc3ccf5cce7ccdbcc81054228cca648ccfdcca2774138cc93ccc5cc947bccef787e6acca6643fccb3ccdeccea0e12cc851cccce3664cc91cccf56ccb7766b255a6862cce1ccf52a63043a0d42063055ccc17f3cccdc305437cc8556ccd6cca5ccfbccfd25cc91cccf794373cc9cccd7cc9f0dccceccf664cc9262ccaaccb6511accf233ccc1ccdf15cccbccf53bccb04f2c553c31ccb9cc9f720c18ccedccc7ccd8cce4ccf4ccecccdecc94756c1dccda2b32ccaaccd3ccdbccf8001326465acc9bcca6ccb0ccdbccf52eccc4ccd6ccdccce820cc8eccb6ccb907081f27313a585acc92cc99ccc2ccc518304760cc98cc9a00000000000000000000000006101519252b00c001e5019301939400dc00201111111111111111111111111111111111111111111111111111111111111111dc00202121212121212121212121212121212121212121212121212121212121212121cd0fa09401dc00201212121212121212121212121212121212121212121212121212121212121212dc00202222222222222222222222222222222222222222222222222222222222222222cd0fa09402dc00201313131313131313131313131313131313131313131313131313131313131313dc00202323232323232323232323232323232323232323232323232323232323232323cd0f9fc0010303030303030303030303030303030303030303030303030303030303030303";
    }

    /// Envelopes as an upload builds them, from `EnvelopeOptions::private()`,
    /// `unlisted()` and `listed()` with the golden metadata, are byte for
    /// byte the ones darwin-listings v0.2.1 writes and darwin-node reads,
    /// at the same addresses; so are the data maps, the salted hash and a
    /// private `.record`.
    #[test]
    fn envelope_bytes_are_darwin_listings_v2s() {
        let hex = |text: &str| hex::decode(text).unwrap();
        let map = golden::data_map();
        let map_bytes = hex(golden::DATA_MAP);
        assert_eq!(ant_listings::encode_data_map(&map).unwrap(), map_bytes);
        assert_eq!(
            ant_listings::encode_data_map(&golden::child_map()).unwrap(),
            hex(golden::CHILD_MAP)
        );
        assert_eq!(
            ant_listings::salted_hash(&golden::SALT, &map_bytes).to_vec(),
            hex(golden::SALTED_HASH)
        );

        for (options, salt, bytes, address) in [
            (
                EnvelopeOptions::private(),
                Some(&golden::SALT),
                golden::PRIVATE_ENVELOPE,
                golden::PRIVATE_ADDRESS,
            ),
            (
                EnvelopeOptions::unlisted(),
                None,
                golden::UNLISTED_ENVELOPE,
                golden::UNLISTED_ADDRESS,
            ),
            (
                EnvelopeOptions::listed(),
                None,
                golden::LISTED_ENVELOPE,
                golden::LISTED_ADDRESS,
            ),
        ] {
            let envelope = options
                .with_metadata(golden::metadata())
                .envelope(&map, salt)
                .unwrap();
            let (at, stored) = crate::client_engine::files::envelope_record(&envelope);
            assert_eq!(stored.to_vec(), hex(bytes), "{address}");
            assert_eq!(at.to_vec(), hex(address));
        }

        let record = EnvelopeProof::from_hex(golden::PRIVATE_RECORD).unwrap();
        assert_eq!(record.to_hex().unwrap(), golden::PRIVATE_RECORD);
        assert_eq!(record.address.to_vec(), hex(golden::PRIVATE_ADDRESS));
        assert_eq!(record.envelope, hex(golden::PRIVATE_ENVELOPE));
        assert_eq!(record.tx_hash, golden::PRIVATE_RECORD_TX);
        assert_eq!(record.data_map.as_deref(), Some(map_bytes.as_slice()));
        assert_eq!(record.salt, Some(golden::SALT));
    }

    /// Uploads are paid per chunk unless a caller chooses otherwise: the
    /// library's default payment mode is Single, never merkle or auto.
    #[test]
    fn the_default_payment_mode_is_per_chunk() {
        assert_eq!(
            crate::data::client::merkle::PaymentMode::default(),
            crate::data::client::merkle::PaymentMode::Single
        );
    }
}
