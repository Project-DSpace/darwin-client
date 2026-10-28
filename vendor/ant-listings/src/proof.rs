//! Proofs of upload: what an uploader keeps so that anyone can check a file
//! against its envelope and payment with only the chain.
//!
//! A proof holds the envelope's bytes, the payment's tx hash and the paid
//! quote, and for an envelope that withholds its data map, the data map and
//! salt that reveal it. It works when the network has lost or withholds the
//! listing, and for fields the uploader hid: the uploader can still prove
//! them to whoever they choose. Checking it needs the receipt of its tx hash
//! and that block's timestamp ([`check_proof`]).
//!
//! A proof travels between programs as text: [`EnvelopeProof::to_hex`], the
//! lowercase hex of [`EnvelopeProof::to_bytes`]. A proof file holds that
//! text, and a JSON field carries it as a string. Use this form, not the serde
//! derives, which give number arrays in JSON.
//!
//! What a proof proves is limited. Its quote shows that the envelope's
//! address was paid for by the block it was paid in, not that this was the
//! upload's payment. Paying a quote needs only the address, and the address
//! is known before the upload is paid: the uploader sends it to each node it
//! asks for a quote, and a gateway that builds the envelope knows it too. Any
//! of them can sign a quote of their own for it, pay it to themselves before
//! the uploader does, and write a proof that checks out; anyone who fetches
//! the envelope can do so later. So of two proofs for one address, the one
//! paid first is not necessarily the upload's: its payment only dates when
//! the address was known. The upload's payment is the one the nodes nearest
//! the address recorded from its PUT, which their listing shows if it shows
//! the quote. Only a reveal, the data map and salt of an envelope that
//! withholds its data map, shows who uploaded the file: a proof without one
//! says nothing about that.

use crate::envelope::{Envelope, EnvelopeError, Salt};
use crate::listing::Payment;
use crate::payment::{
    check_quote, decode_quote, encode_quote, paying_log, pays, PaidAt, PaymentError,
    PaymentReceipt, VaultSet,
};
use ant_protocol::evm::PaymentQuote;
use ant_protocol::XorName;
use self_encryption::DataMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The format version [`EnvelopeProof::to_bytes`] writes first.
pub const PROOF_VERSION: u8 = 1;

/// A record of an upload's envelope and payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeProof {
    /// The file's address: the envelope's hash.
    pub address: XorName,
    /// The envelope's bytes, exactly as stored.
    pub envelope: Vec<u8>,
    /// The payment transaction.
    pub tx_hash: [u8; 32],
    /// The paid quote for the envelope chunk, msgpack-encoded as in payment
    /// proofs, with its timestamp truncated to whole seconds
    /// ([`EnvelopeProof::new`] does this).
    pub quote: Vec<u8>,
    /// For an envelope that withholds its data map: the data map's bytes, as
    /// [`encode_data_map`](crate::encode_data_map) gives them. Revealing it
    /// lets anyone read the file.
    pub data_map: Option<Vec<u8>>,
    /// For an envelope that withholds its data map: the salt it was hashed
    /// with.
    pub salt: Option<Salt>,
}

/// What a valid proof proves.
#[derive(Debug, Clone)]
pub struct ProvenUpload {
    /// The file's address.
    pub address: XorName,
    /// The envelope, with its flags and metadata.
    pub envelope: Envelope,
    /// The data map: the envelope's own, or the revealed one. `None` when the
    /// envelope withholds it and the proof doesn't reveal it: the proof then
    /// shows that the envelope was paid for, but not which file it is.
    pub data_map: Option<DataMap>,
    /// A full payment for the envelope's address, hidden fields included: the
    /// address was paid for by this block. Not necessarily the upload's
    /// payment, which may be earlier or later (see the [module docs](self)).
    pub payment: Payment,
}

impl ProvenUpload {
    /// Where the proof's quote was paid: the address was paid for by then.
    /// An earlier payment for the address doesn't make this one any less
    /// the upload's, since a node asked to quote can pay first.
    #[must_use]
    pub fn paid_at(&self) -> PaidAt {
        PaidAt {
            block_number: self.payment.block_number,
            log_index: self.payment.log_index,
        }
    }
}

/// Why a proof doesn't check out.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofError {
    /// The envelope is invalid, or the revealed data map and salt don't
    /// match it.
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    /// The envelope doesn't hash to the proof's address.
    #[error("the envelope does not hash to the address")]
    WrongAddress,
    /// Only one of the data map and the salt is given.
    #[error("a withheld data map is revealed by both its bytes and the salt")]
    IncompleteReveal,
    /// A data map or salt is given for an envelope that carries its data map.
    #[error("the envelope carries its data map, so the proof must not reveal one")]
    UnexpectedReveal,
    /// The payment doesn't check out.
    #[error("payment: {0}")]
    Payment(#[from] PaymentError),
    /// [`EnvelopeProof::from_bytes`] met a format version it doesn't know.
    #[error("unsupported proof version {0}")]
    UnsupportedVersion(u8),
    /// The proof can't be encoded.
    #[error("cannot encode proof: {0}")]
    Encode(String),
    /// The bytes are not a proof.
    #[error("cannot decode proof: {0}")]
    Decode(String),
}

impl EnvelopeProof {
    /// The proof for `envelope`, paid in `tx_hash` with `quote`, the quote
    /// paid for the envelope chunk. For an envelope that withholds its data
    /// map, add the reveal with [`with_reveal`](Self::with_reveal). The
    /// quote is stored with its timestamp truncated to whole seconds, which
    /// is all its signature and hash cover, so each proof has one encoding.
    ///
    /// The quote is checked here, since the uploader can't rebuild the
    /// record once it is gone: an upload under 64 chunks pays the envelope
    /// in the same transaction as every content chunk, so it is easy to pick
    /// a content chunk's quote. Prefer [`from_payment`](Self::from_payment)
    /// with what [`find_payment`](crate::find_payment) finds in the
    /// uploader's own receipt: the quote the nodes record. Either way, run
    /// [`check_proof`] on the record before saving it, which also checks
    /// that the quote was paid.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Payment`] with [`PaymentError::WrongContent`]
    /// if the quote is for another address, [`PaymentError::BadSignature`]
    /// if its signature is invalid, or [`PaymentError::BadQuote`] if it
    /// can't be encoded.
    pub fn new(
        envelope: &Envelope,
        tx_hash: [u8; 32],
        quote: &PaymentQuote,
    ) -> Result<Self, ProofError> {
        let address = envelope.address();
        check_quote(quote, &address)?;
        Ok(Self {
            address,
            envelope: envelope.to_bytes(),
            tx_hash,
            quote: encode_quote(quote)?,
            data_map: None,
            salt: None,
        })
    }

    /// The proof for `envelope` paid by `payment`, the full payment
    /// [`find_payment`](crate::find_payment) finds for it in the uploader's
    /// own receipt: the same quote the nodes record at upload.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new), and [`PaymentError::BadQuote`] if the
    /// payment's quote doesn't decode.
    pub fn from_payment(envelope: &Envelope, payment: &Payment) -> Result<Self, ProofError> {
        Self::new(envelope, payment.tx_hash, &decode_quote(&payment.quote)?)
    }

    /// This proof with a withheld data map revealed: the data map's bytes, as
    /// [`encode_data_map`](crate::encode_data_map) gives them, and the salt.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::UnexpectedReveal`] if the envelope carries its
    /// data map, [`ProofError::Envelope`] with
    /// [`EnvelopeError::RevealMismatch`] if the data map and salt don't give
    /// its salted hash, and [`ProofError::Envelope`] if the envelope doesn't
    /// parse or the data map is invalid.
    pub fn with_reveal(self, data_map_bytes: Vec<u8>, salt: Salt) -> Result<Self, ProofError> {
        let envelope = Envelope::from_bytes(&self.envelope)?;
        match envelope.check_reveal(&data_map_bytes, &salt) {
            Ok(_) => {}
            Err(EnvelopeError::NotWithheld) => return Err(ProofError::UnexpectedReveal),
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            data_map: Some(data_map_bytes),
            salt: Some(salt),
            ..self
        })
    }

    /// The proof as bytes: [`PROOF_VERSION`], then the record encoded with
    /// postcard.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let mut out = vec![PROOF_VERSION];
        let record = postcard::to_stdvec(self).map_err(|e| ProofError::Encode(e.to_string()))?;
        out.extend_from_slice(&record);
        Ok(out)
    }

    /// The proof as text: the lowercase hex of [`to_bytes`](Self::to_bytes).
    /// The form proofs travel in, in files and in JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn to_hex(&self) -> Result<String, ProofError> {
        Ok(encode_hex(&self.to_bytes()?))
    }

    /// Read [`to_hex`](Self::to_hex) back. Leading and trailing whitespace,
    /// such as a file's last newline, is ignored, and upper case hex is
    /// accepted. Doesn't check the proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the text is not hex, or as
    /// [`from_bytes`](Self::from_bytes) does.
    pub fn from_hex(text: &str) -> Result<Self, ProofError> {
        let bytes = decode_hex(text.trim()).ok_or_else(|| ProofError::Decode("not hex".into()))?;
        Self::from_bytes(&bytes)
    }

    /// Read [`to_bytes`](Self::to_bytes) back. Doesn't check the proof.
    /// Only the bytes `to_bytes` gives are accepted, so one proof has one
    /// encoding, and so one text: postcard would also read a length written
    /// with more bytes than it needs, such as `82 00` for 2.
    ///
    /// # Errors
    ///
    /// Returns an error for another format version, or bytes that are not
    /// exactly one record as `to_bytes` encodes it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let (&version, record) = bytes
            .split_first()
            .ok_or_else(|| ProofError::Decode("empty".into()))?;
        if version != PROOF_VERSION {
            return Err(ProofError::UnsupportedVersion(version));
        }
        let (proof, rest) =
            postcard::take_from_bytes(record).map_err(|e| ProofError::Decode(e.to_string()))?;
        if !rest.is_empty() {
            return Err(ProofError::Decode(format!(
                "{} bytes after the record",
                rest.len()
            )));
        }
        let canonical =
            postcard::to_stdvec(&proof).map_err(|e| ProofError::Decode(e.to_string()))?;
        if canonical != record {
            return Err(ProofError::Decode("not canonical".into()));
        }
        Ok(proof)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Hex digits, either case, two per byte. `None` for anything else.
pub(crate) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let text = text.as_bytes();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, _) = text.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[high, low]| Some(digit(high)? << 4 | digit(low)?))
        .collect()
}

/// Check a proof against the chain alone: `receipt` is the receipt of the
/// proof's tx hash, and `block_timestamp` its block's timestamp.
///
/// 1. The envelope parses and hashes to the proof's address.
/// 2. If it withholds its data map and the proof reveals it, the data map and
///    salt give its salted hash.
/// 3. The quote names the address and is signed by the key it carries.
/// 4. The transaction succeeded and paid the quote to a vault in `vaults`: to
///    the per-quote vault, or to the root vault in a wave the receipt shows
///    whole, transfers included
///    ([`recorded_wave`](crate::root::recorded_wave)).
///
/// Returns the envelope, the data map and the full payment. That shows the
/// address was paid for by the payment's block. Other payments for it, earlier
/// or later, may exist, and only a reveal shows who uploaded the file (see
/// the [module docs](self)).
///
/// # Errors
///
/// Returns the first check that fails.
pub fn check_proof(
    proof: &EnvelopeProof,
    receipt: &PaymentReceipt,
    block_timestamp: u64,
    vaults: &VaultSet,
) -> Result<ProvenUpload, ProofError> {
    let envelope = Envelope::from_bytes(&proof.envelope)?;
    let address = envelope.address();
    if address != proof.address {
        return Err(ProofError::WrongAddress);
    }
    let data_map = if envelope.is_withheld() {
        match (&proof.data_map, &proof.salt) {
            (Some(data_map), Some(salt)) => Some(envelope.check_reveal(data_map, salt)?),
            (None, None) => None,
            _ => return Err(ProofError::IncompleteReveal),
        }
    } else {
        if proof.data_map.is_some() || proof.salt.is_some() {
            return Err(ProofError::UnexpectedReveal);
        }
        envelope.data_map().cloned()
    };

    let quote = decode_quote(&proof.quote)?;
    check_quote(&quote, &address)?;
    if receipt.tx_hash != proof.tx_hash {
        return Err(PaymentError::WrongTransaction.into());
    }
    if !receipt.success {
        return Err(PaymentError::Failed.into());
    }
    let log = paying_log(receipt, vaults, |log, vault| pays(log, vault, &quote))?;
    Ok(ProvenUpload {
        address,
        envelope,
        data_map,
        payment: Payment {
            tx_hash: receipt.tx_hash,
            block_number: receipt.block_number,
            block_timestamp,
            log_index: log.log_index,
            quote: encode_quote(&quote)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{encode_data_map, Metadata};
    use crate::flags::{Flags, PaymentField, ShownFields};
    use crate::listing::Listing;
    use crate::payment::{
        find_payment, payment_lookup, verify_listing_receipts, CheckLevel, ListingCheck, Lookup,
    };
    use crate::test_support::{
        data_map, metadata, payment_log, receipt, signed_quote, BLOCK_TIME, VAULTS,
    };
    use ant_protocol::evm::Amount;

    const TX: [u8; 32] = [0x42; 32];
    const BLOCK: u64 = 500;
    const SALT: Salt = [0x5a; 32];

    struct Upload {
        envelope: Envelope,
        proof: EnvelopeProof,
        receipt: PaymentReceipt,
        map: DataMap,
        quote: PaymentQuote,
        /// The quote for a content chunk, paid in the same transaction.
        content: PaymentQuote,
    }

    /// An upload out of the index, hiding all five fields.
    fn upload(withheld: bool) -> Upload {
        upload_with(Flags {
            shown: ShownFields::NONE,
            in_index: false,
            withheld,
        })
    }

    /// An upload with these flags, paid at log index 2 of a transaction that
    /// also pays a content chunk at index 1.
    fn upload_with(flags: Flags) -> Upload {
        let map = data_map(&[10, 20, 30]);
        let meta = metadata(Some("text/plain"), None);
        let envelope = if flags.withheld {
            Envelope::withheld(&map, &SALT, meta, flags.shown, flags.in_index).unwrap()
        } else {
            Envelope::readable(&map, meta, flags.shown, flags.in_index).unwrap()
        };
        let quote = signed_quote(envelope.address());
        let content = signed_quote([3; 32]);
        let receipt = receipt(
            TX,
            BLOCK,
            vec![payment_log(&content, 1), payment_log(&quote, 2)],
        );
        let mut proof = EnvelopeProof::new(&envelope, TX, &quote).unwrap();
        if flags.withheld {
            proof = proof
                .with_reveal(encode_data_map(&map).unwrap(), SALT)
                .unwrap();
        }
        Upload {
            envelope,
            proof,
            receipt,
            map,
            quote,
            content,
        }
    }

    #[test]
    fn proves_every_flags_byte_and_rebuilds_its_listing() {
        let now = BLOCK_TIME + 30;
        for byte in 0..Flags::RESERVED {
            let flags = Flags::from_byte(byte).unwrap();
            let upload = upload_with(flags);
            let proven = check_proof(&upload.proof, &upload.receipt, BLOCK_TIME, &VAULTS).unwrap();
            assert_eq!(proven.address, upload.proof.address);
            assert_eq!(proven.envelope.to_bytes(), upload.proof.envelope);
            assert_eq!(proven.envelope.flags(), flags);
            assert_eq!(proven.data_map, Some(upload.map.clone()));
            let paid_at = PaidAt {
                block_number: BLOCK,
                log_index: 2,
            };
            assert_eq!(proven.paid_at(), paid_at);
            assert_eq!(
                proven.payment,
                Payment {
                    tx_hash: TX,
                    block_number: BLOCK,
                    block_timestamp: BLOCK_TIME,
                    log_index: 2,
                    quote: encode_quote(&upload.quote).unwrap(),
                }
            );
            // It is the payment a node finds at upload...
            let found = find_payment(
                &proven.address,
                &[upload.content.clone(), upload.quote.clone()],
                &upload.receipt,
                BLOCK_TIME,
                &VAULTS,
            )
            .unwrap();
            assert_eq!(proven.payment, found);
            // ...so a proof built from it is the same record, unrevealed.
            let rebuilt = EnvelopeProof::from_payment(&proven.envelope, &found).unwrap();
            assert_eq!(
                rebuilt,
                EnvelopeProof {
                    data_map: None,
                    salt: None,
                    ..upload.proof.clone()
                }
            );

            // And it gives the listing a node records, which checks out
            // against the chain as far as its flags allow.
            let listing = Listing::new(&proven.envelope, &proven.payment, now);
            assert!(listing.matches(&proven.envelope));
            let found_receipt = (Some(upload.receipt.clone()), Some(BLOCK_TIME));
            let fetched = match payment_lookup(&listing).unwrap() {
                Lookup::Transaction { .. } | Lookup::Quote { .. } | Lookup::BlockLog { .. } => {
                    vec![found_receipt]
                }
                Lookup::Block { .. } => vec![(None, Some(BLOCK_TIME))],
                Lookup::Nothing => Vec::new(),
            };
            let check = verify_listing_receipts(&listing, &proven.envelope, &fetched, &VAULTS, now);
            let expected = if flags.shown.contains(PaymentField::Quote) {
                ListingCheck {
                    level: CheckLevel::Verified,
                    paid_at: Some(paid_at),
                }
            } else {
                ListingCheck {
                    level: CheckLevel::Reported,
                    paid_at: None,
                }
            };
            assert_eq!(check, Ok(expected), "{flags:?}");
        }
    }

    #[test]
    fn new_refuses_a_quote_that_is_not_the_envelopes() {
        for withheld in [false, true] {
            let upload = upload(withheld);
            let envelope = &upload.envelope;
            // The content chunk's quote, paid in the same transaction: easy
            // to pick by mistake, and useless as a proof.
            assert_eq!(
                EnvelopeProof::new(envelope, TX, &upload.content),
                Err(ProofError::Payment(PaymentError::WrongContent))
            );
            // A quote whose signature doesn't cover it.
            let mut forged = upload.quote.clone();
            forged.price = Amount::from(1u64);
            assert_eq!(
                EnvelopeProof::new(envelope, TX, &forged),
                Err(ProofError::Payment(PaymentError::BadSignature))
            );
            let mut unsigned = upload.quote.clone();
            unsigned.signature.clear();
            assert_eq!(
                EnvelopeProof::new(envelope, TX, &unsigned),
                Err(ProofError::Payment(PaymentError::BadSignature))
            );
            // From a payment, too: another chunk's, or one whose quote
            // doesn't decode.
            let content_payment = find_payment(
                &[3; 32],
                std::slice::from_ref(&upload.content),
                &upload.receipt,
                BLOCK_TIME,
                &VAULTS,
            )
            .unwrap();
            assert_eq!(
                EnvelopeProof::from_payment(envelope, &content_payment),
                Err(ProofError::Payment(PaymentError::WrongContent))
            );
            let garbled = Payment {
                quote: vec![0xc1],
                ..content_payment
            };
            assert!(matches!(
                EnvelopeProof::from_payment(envelope, &garbled),
                Err(ProofError::Payment(PaymentError::BadQuote(_)))
            ));
        }
    }

    #[test]
    fn with_reveal_refuses_a_reveal_that_does_not_match() {
        let upload = upload(true);
        let unrevealed = EnvelopeProof::new(&upload.envelope, TX, &upload.quote).unwrap();
        let map_bytes = encode_data_map(&upload.map).unwrap();
        assert_eq!(
            unrevealed.clone().with_reveal(map_bytes.clone(), SALT),
            Ok(upload.proof.clone())
        );

        let mismatch = Err(ProofError::Envelope(EnvelopeError::RevealMismatch));
        let mut wrong_salt = SALT;
        wrong_salt[0] ^= 1;
        assert_eq!(
            unrevealed
                .clone()
                .with_reveal(map_bytes.clone(), wrong_salt),
            mismatch
        );
        let other_map = encode_data_map(&data_map(&[10, 20, 31])).unwrap();
        assert_eq!(unrevealed.clone().with_reveal(other_map, SALT), mismatch);
        // A salt regenerated after hashing is just as wrong.
        assert_eq!(
            unrevealed
                .clone()
                .with_reveal(map_bytes.clone(), [0x5b; 32]),
            mismatch
        );

        // Nothing to reveal for an envelope that carries its data map.
        let readable = upload_with(Flags {
            shown: ShownFields::ALL,
            in_index: true,
            withheld: false,
        });
        assert_eq!(
            readable.proof.with_reveal(map_bytes.clone(), SALT),
            Err(ProofError::UnexpectedReveal)
        );

        // A record whose envelope doesn't parse can't take a reveal.
        let mut broken = unrevealed;
        broken.envelope[0] = 1;
        assert_eq!(
            broken.with_reveal(map_bytes, SALT),
            Err(ProofError::Envelope(EnvelopeError::NotAnEnvelope))
        );
    }

    #[test]
    fn a_withheld_upload_can_be_proved_without_revealing_it() {
        let mut upload = upload(true);
        upload.proof.data_map = None;
        upload.proof.salt = None;
        let proven = check_proof(&upload.proof, &upload.receipt, BLOCK_TIME, &VAULTS).unwrap();
        assert_eq!(proven.data_map, None);
        assert_eq!(proven.payment.log_index, 2);
    }

    #[test]
    fn rejects_tampered_proofs() {
        let check = |proof: &EnvelopeProof, receipt: &PaymentReceipt| {
            check_proof(proof, receipt, BLOCK_TIME, &VAULTS)
        };
        for withheld in [false, true] {
            let upload = upload(withheld);
            let good = &upload.proof;
            let receipt = &upload.receipt;
            assert!(check(good, receipt).is_ok());

            let mut envelope = good.clone();
            *envelope.envelope.last_mut().unwrap() ^= 1;
            assert!(check(&envelope, receipt).is_err());

            let mut not_an_envelope = good.clone();
            not_an_envelope.envelope[0] = 1;
            assert_eq!(
                check(&not_an_envelope, receipt).unwrap_err(),
                ProofError::Envelope(EnvelopeError::NotAnEnvelope)
            );

            let mut address = good.clone();
            address.address[0] ^= 1;
            assert_eq!(
                check(&address, receipt).unwrap_err(),
                ProofError::WrongAddress
            );

            let mut other_tx = receipt.clone();
            other_tx.tx_hash = [1; 32];
            assert_eq!(
                check(good, &other_tx).unwrap_err(),
                ProofError::Payment(PaymentError::WrongTransaction)
            );

            let mut failed = receipt.clone();
            failed.success = false;
            assert_eq!(
                check(good, &failed).unwrap_err(),
                ProofError::Payment(PaymentError::Failed)
            );

            let mut unpaid = good.clone();
            unpaid.quote = encode_quote(&signed_quote(good.address)).unwrap();
            assert_eq!(
                check(&unpaid, receipt).unwrap_err(),
                ProofError::Payment(PaymentError::NotPaid)
            );

            let mut other_address = good.clone();
            other_address.quote = encode_quote(&signed_quote([3; 32])).unwrap();
            assert_eq!(
                check(&other_address, receipt).unwrap_err(),
                ProofError::Payment(PaymentError::WrongContent)
            );

            let mut forged_quote = upload.quote.clone();
            forged_quote.price = Amount::from(1u64);
            let mut forged = good.clone();
            forged.quote = encode_quote(&forged_quote).unwrap();
            assert_eq!(
                check(&forged, receipt).unwrap_err(),
                ProofError::Payment(PaymentError::BadSignature)
            );

            let mut garbled = good.clone();
            garbled.quote = vec![0xc1];
            assert!(matches!(
                check(&garbled, receipt),
                Err(ProofError::Payment(PaymentError::BadQuote(_)))
            ));

            assert_eq!(
                check_proof(good, receipt, BLOCK_TIME, &VaultSet::v2_only([0x11; 20])).unwrap_err(),
                ProofError::Payment(PaymentError::UnknownVault)
            );
        }
    }

    #[test]
    fn rejects_bad_reveals() {
        let check = |proof: &EnvelopeProof, receipt: &PaymentReceipt| {
            check_proof(proof, receipt, BLOCK_TIME, &VAULTS)
        };
        let upload = upload(true);
        let good = &upload.proof;
        let receipt = &upload.receipt;

        let mut wrong_salt = good.clone();
        wrong_salt.salt = Some([0; 32]);
        assert_eq!(
            check(&wrong_salt, receipt).unwrap_err(),
            ProofError::Envelope(EnvelopeError::RevealMismatch)
        );

        let mut wrong_map = good.clone();
        wrong_map.data_map = Some(encode_data_map(&data_map(&[10, 20, 31])).unwrap());
        assert_eq!(
            check(&wrong_map, receipt).unwrap_err(),
            ProofError::Envelope(EnvelopeError::RevealMismatch)
        );

        for (data_map, salt) in [(good.data_map.clone(), None), (None, good.salt)] {
            let mut incomplete = good.clone();
            incomplete.data_map = data_map;
            incomplete.salt = salt;
            assert_eq!(
                check(&incomplete, receipt).unwrap_err(),
                ProofError::IncompleteReveal
            );
        }

        let readable = upload_readable_with(good.data_map.clone(), good.salt);
        assert_eq!(
            check(&readable.0, &readable.1).unwrap_err(),
            ProofError::UnexpectedReveal
        );
        let readable = upload_readable_with(None, Some(SALT));
        assert_eq!(
            check(&readable.0, &readable.1).unwrap_err(),
            ProofError::UnexpectedReveal
        );
    }

    fn upload_readable_with(
        data_map: Option<Vec<u8>>,
        salt: Option<Salt>,
    ) -> (EnvelopeProof, PaymentReceipt) {
        let upload = upload(false);
        let mut proof = upload.proof;
        proof.data_map = data_map;
        proof.salt = salt;
        (proof, upload.receipt)
    }

    #[test]
    fn proofs_round_trip_as_bytes() {
        for withheld in [false, true] {
            let proof = upload(withheld).proof;
            let bytes = proof.to_bytes().unwrap();
            assert_eq!(bytes[0], PROOF_VERSION);
            assert_eq!(EnvelopeProof::from_bytes(&bytes).unwrap(), proof);

            let mut later = bytes.clone();
            later[0] = 2;
            assert_eq!(
                EnvelopeProof::from_bytes(&later).unwrap_err(),
                ProofError::UnsupportedVersion(2)
            );
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(matches!(
                EnvelopeProof::from_bytes(&trailing),
                Err(ProofError::Decode(_))
            ));
            for len in 0..bytes.len() {
                assert!(EnvelopeProof::from_bytes(&bytes[..len]).is_err(), "{len}");
            }
        }
    }

    #[test]
    fn proofs_round_trip_as_hex() {
        for withheld in [false, true] {
            let upload = upload(withheld);
            let proof = upload.proof;
            let hex = proof.to_hex().unwrap();
            assert_eq!(hex, encode_hex(&proof.to_bytes().unwrap()));
            assert!(hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            assert_eq!(EnvelopeProof::from_hex(&hex).unwrap(), proof);
            assert_eq!(EnvelopeProof::from_hex(&format!("{hex}\n")).unwrap(), proof);
            assert_eq!(EnvelopeProof::from_hex(&hex.to_uppercase()).unwrap(), proof);
            for bad in [
                hex[1..].to_string(),
                format!("{hex}0"),
                format!("x{}", &hex[1..]),
                format!("{} {}", &hex[..2], &hex[2..]),
            ] {
                assert_eq!(
                    EnvelopeProof::from_hex(&bad).unwrap_err(),
                    ProofError::Decode("not hex".into())
                );
            }
            // Read from its text, it checks out.
            let read = EnvelopeProof::from_hex(&hex).unwrap();
            assert!(check_proof(&read, &upload.receipt, BLOCK_TIME, &VAULTS).is_ok());
        }
        assert_eq!(decode_hex(""), Some(Vec::new()));
        assert_eq!(decode_hex("00ff7fA0"), Some(vec![0, 0xff, 0x7f, 0xa0]));
        assert_eq!(encode_hex(&[0, 0xff, 0x7f, 0xa0]), "00ff7fa0");
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("é0"), None);
    }

    #[test]
    fn proof_layout_is_fixed() {
        let readable = EnvelopeProof {
            address: [0x01; 32],
            envelope: vec![0x02, 0x03],
            tx_hash: [0x04; 32],
            quote: vec![0x05, 0x06, 0x07],
            data_map: None,
            salt: None,
        };
        let expected = concat!(
            "01", // format version
            "0101010101010101010101010101010101010101010101010101010101010101",
            "020203", // envelope
            "0404040404040404040404040404040404040404040404040404040404040404",
            "03050607", // quote
            "00",       // no data map
            "00",       // no salt
        );
        assert_eq!(readable.to_hex().unwrap(), expected);
        assert_eq!(EnvelopeProof::from_hex(expected).unwrap(), readable);

        let withheld = EnvelopeProof {
            data_map: Some(vec![0x08, 0x09]),
            salt: Some([0x0a; 32]),
            ..readable
        };
        let expected = concat!(
            "01",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "020203",
            "0404040404040404040404040404040404040404040404040404040404040404",
            "03050607",
            "01020809", // data map
            "01",       // salt
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        );
        assert_eq!(withheld.to_hex().unwrap(), expected);
        assert_eq!(EnvelopeProof::from_hex(expected).unwrap(), withheld);
    }

    #[test]
    fn overlong_lengths_are_refused() {
        // The golden readable proof, as proof_layout_is_fixed has it.
        let address = "0101010101010101010101010101010101010101010101010101010101010101";
        let tx = "0404040404040404040404040404040404040404040404040404040404040404";
        let salt = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
        let proof = |envelope_len: &str, quote_len: &str, reveal: &str| {
            format!("01{address}{envelope_len}0203{tx}{quote_len}050607{reveal}")
        };
        let canonical = proof("02", "03", "0000");
        let read = EnvelopeProof::from_hex(&canonical).unwrap();
        assert_eq!(read.to_hex().unwrap(), canonical);
        let canonical_reveal = proof("02", "03", &format!("0102080901{salt}"));
        let revealed = EnvelopeProof::from_hex(&canonical_reveal).unwrap();
        assert_eq!(revealed.to_hex().unwrap(), canonical_reveal);

        // The same lengths, written with more bytes than they need: postcard
        // reads them as the same proof, from other bytes.
        for other in [
            proof("8200", "03", "0000"),
            proof("828000", "03", "0000"),
            proof("02", "8300", "0000"),
            proof("02", "03", &format!("01{}01{salt}", "82000809")),
        ] {
            let bytes = decode_hex(&other).unwrap();
            let (lenient, rest) = postcard::take_from_bytes::<EnvelopeProof>(&bytes[1..]).unwrap();
            assert!(rest.is_empty());
            assert!(lenient == read || lenient == revealed, "{other}");
            assert_eq!(
                EnvelopeProof::from_hex(&other),
                Err(ProofError::Decode("not canonical".into())),
                "{other}"
            );
        }
    }

    #[test]
    fn rejects_quotes_that_are_not_canonical() {
        let upload = upload(false);
        let mut trailing = upload.proof.clone();
        trailing.quote.push(0);
        assert_eq!(
            check_proof(&trailing, &upload.receipt, BLOCK_TIME, &VAULTS).unwrap_err(),
            ProofError::Payment(PaymentError::BadQuote("not canonical".into()))
        );
    }

    #[test]
    fn proofs_carry_what_the_uploader_needs() {
        let upload = upload(false);
        let proof = &upload.proof;
        let envelope = Envelope::from_bytes(&proof.envelope).unwrap();
        assert_eq!(proof.address, envelope.address());
        assert_eq!(proof.tx_hash, TX);
        assert_eq!(decode_quote(&proof.quote).unwrap(), upload.quote);
        assert_eq!(proof.data_map, None);
        assert_eq!(proof.salt, None);
        assert_eq!(envelope.metadata(), &metadata(Some("text/plain"), None));
        assert_ne!(envelope.metadata(), &Metadata::default());
    }
}
