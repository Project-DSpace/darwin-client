//! An envelope's flags: which payment fields its listing shows, whether the
//! listing is in the index, and whether the data map is withheld.
//!
//! One byte, version 2 envelopes onwards:
//!
//! | Bit | Set means |
//! |---|---|
//! | 0 | the tx hash is shown |
//! | 1 | the block number is shown |
//! | 2 | the block timestamp is shown |
//! | 3 | the log index is shown |
//! | 4 | the paid quote is shown |
//! | 5 | the listing is in the index |
//! | 6 | the data map is withheld: the envelope ends with its salted hash |
//! | 7 | reserved, must be zero |
//!
//! The flags are part of the envelope's bytes, so they are part of its
//! address: fixed at upload, and no node can change them.

use crate::envelope::EnvelopeError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// One of the five payment fields a listing can show or hide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaymentField {
    /// The payment transaction's hash. Bit 0.
    TxHash,
    /// The block the payment transaction is in. Bit 1.
    BlockNumber,
    /// The block's timestamp. Bit 2.
    BlockTimestamp,
    /// The position in the block of the payment vault's `DataPaymentMade`
    /// event for the envelope chunk. Bit 3.
    LogIndex,
    /// The paid quote. Bit 4.
    Quote,
}

impl PaymentField {
    /// All five, in bit order.
    pub const ALL: [Self; 5] = [
        Self::TxHash,
        Self::BlockNumber,
        Self::BlockTimestamp,
        Self::LogIndex,
        Self::Quote,
    ];

    /// The field's bit in the flags byte.
    #[must_use]
    pub const fn bit(self) -> u8 {
        1 << (self as u8)
    }

    /// The field's name in command lines and requests: `tx-hash`, `block`,
    /// `timestamp`, `log-index` or `quote`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TxHash => "tx-hash",
            Self::BlockNumber => "block",
            Self::BlockTimestamp => "timestamp",
            Self::LogIndex => "log-index",
            Self::Quote => "quote",
        }
    }

    /// The field with this [`name`](Self::name), if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.name() == name)
    }
}

impl fmt::Display for PaymentField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which of the five payment fields a listing shows: bits 0 to 4 of the
/// flags. All five by default.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct ShownFields(u8);

impl ShownFields {
    /// All five shown.
    pub const ALL: Self = Self(0b1_1111);
    /// All five hidden.
    pub const NONE: Self = Self(0);

    /// The set with these bits, or `None` if a bit above 4 is set.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// The set's bits, 0 to 4.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether `field` is shown.
    #[must_use]
    pub const fn contains(self, field: PaymentField) -> bool {
        self.0 & field.bit() != 0
    }

    /// This set with `field` shown.
    #[must_use]
    pub const fn with(self, field: PaymentField) -> Self {
        Self(self.0 | field.bit())
    }

    /// This set with `field` hidden.
    #[must_use]
    pub const fn without(self, field: PaymentField) -> Self {
        Self(self.0 & !field.bit())
    }

    /// The shown fields, in bit order.
    pub fn shown(self) -> impl Iterator<Item = PaymentField> {
        PaymentField::ALL
            .into_iter()
            .filter(move |field| self.contains(*field))
    }

    /// The hidden fields, in bit order.
    pub fn hidden(self) -> impl Iterator<Item = PaymentField> {
        PaymentField::ALL
            .into_iter()
            .filter(move |field| !self.contains(*field))
    }

    /// All 32 sets, from none shown to all shown.
    pub fn every() -> impl Iterator<Item = Self> {
        (0..=Self::ALL.0).map(Self)
    }
}

impl Default for ShownFields {
    fn default() -> Self {
        Self::ALL
    }
}

impl fmt::Debug for ShownFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.shown()).finish()
    }
}

impl FromIterator<PaymentField> for ShownFields {
    fn from_iter<I: IntoIterator<Item = PaymentField>>(fields: I) -> Self {
        fields.into_iter().fold(Self::NONE, Self::with)
    }
}

impl TryFrom<u8> for ShownFields {
    type Error = EnvelopeError;

    fn try_from(bits: u8) -> Result<Self, Self::Error> {
        Self::from_bits(bits).ok_or(EnvelopeError::InvalidFlags(bits))
    }
}

impl From<ShownFields> for u8 {
    fn from(shown: ShownFields) -> Self {
        shown.0
    }
}

/// An envelope's flags. Every value is valid; only the reserved bit 7 makes a
/// flags byte invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Flags {
    /// The payment fields the listing shows.
    pub shown: ShownFields,
    /// Whether the listing is in the index. Listings outside it are returned
    /// for their address but left out of list requests.
    pub in_index: bool,
    /// Whether the data map is withheld: the envelope ends with a salted hash
    /// of it instead.
    pub withheld: bool,
}

impl Flags {
    /// Bit 5: in the index.
    pub const IN_INDEX: u8 = 1 << 5;
    /// Bit 6: the data map is withheld.
    pub const WITHHELD: u8 = 1 << 6;
    /// Bit 7: reserved, must be zero.
    pub const RESERVED: u8 = 1 << 7;

    /// What a version 1 envelope counts as: all shown, in the index, with the
    /// data map.
    pub const V1: Self = Self {
        shown: ShownFields::ALL,
        in_index: true,
        withheld: false,
    };

    /// The flags byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        let mut byte = self.shown.bits();
        if self.in_index {
            byte |= Self::IN_INDEX;
        }
        if self.withheld {
            byte |= Self::WITHHELD;
        }
        byte
    }

    /// Read a flags byte.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::InvalidFlags`] if the reserved bit 7 is set.
    pub const fn from_byte(byte: u8) -> Result<Self, EnvelopeError> {
        if byte & Self::RESERVED != 0 {
            return Err(EnvelopeError::InvalidFlags(byte));
        }
        Ok(Self {
            shown: ShownFields(byte & ShownFields::ALL.0),
            in_index: byte & Self::IN_INDEX != 0,
            withheld: byte & Self::WITHHELD != 0,
        })
    }
}

impl TryFrom<u8> for Flags {
    type Error = EnvelopeError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_byte(byte)
    }
}

impl From<Flags> for u8 {
    fn from(flags: Flags) -> Self {
        flags.to_byte()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_flags_byte_round_trips_or_is_rejected() {
        let mut valid = 0;
        for byte in 0..=u8::MAX {
            match Flags::from_byte(byte) {
                Ok(flags) => {
                    valid += 1;
                    assert!(byte & Flags::RESERVED == 0, "{byte:#04x} accepted");
                    assert_eq!(flags.to_byte(), byte);
                    assert_eq!(flags.shown.bits(), byte & 0x1f);
                    assert_eq!(flags.in_index, byte & 0x20 != 0);
                    assert_eq!(flags.withheld, byte & 0x40 != 0);
                    for field in PaymentField::ALL {
                        assert_eq!(flags.shown.contains(field), byte & field.bit() != 0);
                    }
                    let encoded = postcard::to_stdvec(&flags).unwrap();
                    assert_eq!(encoded, [byte]);
                    assert_eq!(postcard::from_bytes::<Flags>(&encoded).unwrap(), flags);
                }
                Err(e) => {
                    assert!(byte & Flags::RESERVED != 0, "{byte:#04x} rejected");
                    assert_eq!(e, EnvelopeError::InvalidFlags(byte));
                    assert!(postcard::from_bytes::<Flags>(&[byte]).is_err());
                }
            }
        }
        assert_eq!(valid, 128);
    }

    #[test]
    fn bits_are_fixed() {
        let bits: Vec<u8> = PaymentField::ALL.iter().map(|f| f.bit()).collect();
        assert_eq!(bits, [1, 2, 4, 8, 16]);
        assert_eq!(Flags::V1.to_byte(), 0b0011_1111);
        let private = Flags {
            shown: ShownFields::ALL,
            in_index: false,
            withheld: true,
        };
        assert_eq!(private.to_byte(), 0b0101_1111);
    }

    #[test]
    fn shown_sets() {
        assert_eq!(ShownFields::every().count(), 32);
        assert_eq!(ShownFields::default(), ShownFields::ALL);
        for bits in 0..=u8::MAX {
            assert_eq!(ShownFields::from_bits(bits).is_some(), bits < 32);
            assert_eq!(ShownFields::try_from(bits).is_ok(), bits < 32);
        }
        for shown in ShownFields::every() {
            let rebuilt: ShownFields = shown.shown().collect();
            assert_eq!(rebuilt, shown);
            assert_eq!(shown.shown().count() + shown.hidden().count(), 5);
            for field in PaymentField::ALL {
                assert!(shown.with(field).contains(field));
                assert!(!shown.without(field).contains(field));
            }
        }
        assert_eq!(
            format!("{:?}", ShownFields::NONE.with(PaymentField::Quote)),
            "{Quote}"
        );
    }

    #[test]
    fn field_names_round_trip() {
        // The words `--hide` and `hide=` take: fixed, since users type them.
        assert_eq!(
            PaymentField::ALL.map(PaymentField::name),
            ["tx-hash", "block", "timestamp", "log-index", "quote"]
        );
        for field in PaymentField::ALL {
            assert_eq!(PaymentField::from_name(field.name()), Some(field));
            assert_eq!(field.to_string(), field.name());
        }
        assert_eq!(PaymentField::from_name("all"), None);
        assert_eq!(PaymentField::from_name("Quote"), None);
    }
}
