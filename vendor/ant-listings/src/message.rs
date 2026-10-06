//! The listings protocol: requests and responses on [`TOPIC`].
//!
//! Messages are encoded with postcard, like the chunk protocol. Enum variants
//! are numbered by position on the wire, so new ones are only ever appended.
//!
//! To page through a node's index, ask from [`ListingKey::MIN`], check each
//! [`ListingsBody::ListResponse`] with [`check_list_page`], and ask again from
//! the key it returns until it returns `None`. Check each
//! [`ListingsBody::GetResponse`] with [`check_get_response`].
//!
//! Each page's keys come after the last page's, so a node can't make a
//! client read a page twice, but it can serve as many listings as it likes:
//! walk with [`IndexWalk`](crate::IndexWalk), which reads each node for as
//! long as other nodes back what it sends.
//!
//! Keys are payment times, not the times a node stored its listings, so a
//! node can store a listing after a walk passed its place, with a key before
//! where the walk stopped: one that hides its time is keyed by the hour it
//! was stored, and one that shows it by its block time, however late its PUT
//! came. To pick up new listings, don't carry on from the last key seen: walk
//! again from [`ListingKey::since`] the time the previous walk began, and
//! drop the listings already seen.

use crate::listing::{Listing, ListingError, ListingKey};
use ant_protocol::{XorName, MAX_WIRE_MESSAGE_SIZE};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The topic listings messages travel on, separate from the chunk protocol's.
/// Version 2 carries version 2 listings and keys; nothing answers
/// `listings.v1` any more.
pub const TOPIC: &str = "listings.v2";

/// The most listings one response carries. A full page of the largest
/// listings stays well under the wire limit.
pub const MAX_LIST_LIMIT: u32 = 256;

/// A request or response, with an id the response echoes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingsMessage {
    /// Chosen by the sender of a request and echoed in the response.
    pub request_id: u64,
    /// The request or response.
    pub body: ListingsBody,
}

/// The requests and responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListingsBody {
    /// Listings in the index with keys from `from` onwards, in key order: at
    /// most `limit`, and never more than [`MAX_LIST_LIMIT`]. Listings outside
    /// the index are never listed.
    ListRequest {
        /// The first key wanted. [`ListingKey::MIN`] for everything; for the
        /// next page, the key [`check_list_page`] returned for the last one.
        from: ListingKey,
        /// The most listings wanted.
        limit: u32,
    },
    /// Listings in key order. `more` is true if the node holds later ones.
    /// Never more than [`MAX_LIST_LIMIT`]: [`ListingsMessage::decode`]
    /// refuses a longer one. Check the rest with [`check_list_page`].
    ListResponse {
        /// The listings.
        listings: Vec<Listing>,
        /// Whether the node holds listings after the last one returned.
        more: bool,
    },
    /// The listing for one address, in the index or not.
    GetRequest {
        /// The file's address.
        address: XorName,
    },
    /// The listing, if the node holds it.
    GetResponse {
        /// The listing.
        listing: Option<Listing>,
    },
    /// The node refused the request.
    Error {
        /// Why.
        message: String,
    },
}

/// Why a message can't be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MessageError {
    /// The message exceeds the wire limit.
    #[error("message is {size} bytes, more than {max}")]
    TooLarge {
        /// The message's size.
        size: usize,
        /// The limit.
        max: usize,
    },
    /// Encoding failed.
    #[error("cannot encode message: {0}")]
    Encode(String),
    /// The bytes are not a valid message.
    #[error("cannot decode message: {0}")]
    Decode(String),
}

/// Why a [`ListingsBody::ListResponse`] or [`ListingsBody::GetResponse`] is
/// not a valid answer to its request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PageError {
    /// More listings than were asked for, or than [`MAX_LIST_LIMIT`].
    #[error("the page has {count} listings, more than {max}")]
    TooMany {
        /// How many the page has.
        count: usize,
        /// The most it may have.
        max: usize,
    },
    /// The listing in a [`ListingsBody::GetResponse`] doesn't fit its
    /// flags. [`check_list_page`] doesn't give this: it leaves invalid
    /// listings to [`merge_copies`](crate::merge_copies).
    #[error("malformed listing: {0}")]
    Malformed(#[from] ListingError),
    /// A listing outside the index, which list requests never return.
    #[error("the page has a listing outside the index")]
    NotInIndex,
    /// A listing with a key before the one asked from.
    #[error("the page has a listing before the key asked from")]
    BeforeFrom,
    /// The keys don't strictly increase.
    #[error("the page's listings are not in key order")]
    OutOfOrder,
    /// The listing in a [`ListingsBody::GetResponse`] is for another address
    /// than the one asked for.
    #[error("the listing is for a different address than the one asked for")]
    WrongAddress,
}

/// Check a page of listings a node returned for `ListRequest { from, limit }`,
/// and say where the next page starts.
///
/// The page must have at most `min(limit, MAX_LIST_LIMIT)` listings, each in
/// the index, with keys from `from` onwards in strictly increasing order.
/// Returns the `from` of the next request: the key after the last listing's,
/// when the node said it has `more` and the page moved on. `None` means this
/// node has no more to give: it said so, the page was empty, or the last key
/// was the largest.
///
/// Only the page's shape is checked, which is what keeps paging safe: each
/// page moves strictly forward, so a walk ends unless the node keeps serving
/// new listings, which [`IndexWalk`](crate::IndexWalk)'s allowances stop. Whether
/// each listing is valid is not: [`merge_copies`](crate::merge_copies) leaves
/// out the invalid ones, so one listing a node carried over from an older
/// version, or that a later version's rules refuse, doesn't hide the rest of
/// that node's index.
///
/// # Errors
///
/// Returns the first problem found. Drop the whole page, and stop paging
/// that node.
pub fn check_list_page(
    from: ListingKey,
    limit: u32,
    listings: &[Listing],
    more: bool,
) -> Result<Option<ListingKey>, PageError> {
    let max = usize::try_from(limit.min(MAX_LIST_LIMIT)).unwrap_or(usize::MAX);
    if listings.len() > max {
        return Err(PageError::TooMany {
            count: listings.len(),
            max,
        });
    }
    let mut last: Option<ListingKey> = None;
    for listing in listings {
        if !listing.flags.in_index {
            return Err(PageError::NotInIndex);
        }
        let key = listing.key();
        if key < from {
            return Err(PageError::BeforeFrom);
        }
        if last.is_some_and(|last| key <= last) {
            return Err(PageError::OutOfOrder);
        }
        last = Some(key);
    }
    Ok(last.filter(|_| more).and_then(ListingKey::checked_next))
}

/// Check the listing a node returned for `GetRequest { address: asked }`: it
/// must be for `asked` and valid ([`Listing::validate`]). Returns it, or
/// `None` if the node has none. Without this check, a node could answer with
/// another file's genuine listing, to be shown under the address asked for.
///
/// # Errors
///
/// Returns [`PageError::WrongAddress`] or [`PageError::Malformed`]. Drop the
/// answer.
pub fn check_get_response(
    asked: &XorName,
    listing: Option<Listing>,
) -> Result<Option<Listing>, PageError> {
    let Some(listing) = listing else {
        return Ok(None);
    };
    if listing.address != *asked {
        return Err(PageError::WrongAddress);
    }
    listing.validate()?;
    Ok(Some(listing))
}

impl ListingsBody {
    /// How many listings a `ListResponse` has, if more than
    /// [`MAX_LIST_LIMIT`].
    fn too_many_listings(&self) -> Option<usize> {
        match self {
            Self::ListResponse { listings, .. } => {
                let max = usize::try_from(MAX_LIST_LIMIT).unwrap_or(usize::MAX);
                (listings.len() > max).then_some(listings.len())
            }
            _ => None,
        }
    }
}

impl ListingsMessage {
    /// Encode for sending.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails, the result exceeds the wire limit,
    /// or it is a `ListResponse` with more than [`MAX_LIST_LIMIT`] listings.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        if let Some(count) = self.body.too_many_listings() {
            return Err(MessageError::Encode(format!(
                "{count} listings in one response, more than {MAX_LIST_LIMIT}"
            )));
        }
        let bytes = postcard::to_stdvec(self).map_err(|e| MessageError::Encode(e.to_string()))?;
        if bytes.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(MessageError::TooLarge {
                size: bytes.len(),
                max: MAX_WIRE_MESSAGE_SIZE,
            });
        }
        Ok(bytes)
    }

    /// Decode received bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes exceed the wire limit, are not a valid
    /// message, or are a `ListResponse` with more than [`MAX_LIST_LIMIT`]
    /// listings.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(MessageError::TooLarge {
                size: bytes.len(),
                max: MAX_WIRE_MESSAGE_SIZE,
            });
        }
        let message: Self =
            postcard::from_bytes(bytes).map_err(|e| MessageError::Decode(e.to_string()))?;
        if let Some(count) = message.body.too_many_listings() {
            return Err(MessageError::Decode(format!(
                "{count} listings in one response, more than {MAX_LIST_LIMIT}"
            )));
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Metadata, MAX_CONTENT_TYPE_LEN, MAX_NAME_LEN};
    use crate::flags::{Flags, PaymentField, ShownFields};
    use crate::listing::ListingPayment;
    use ant_protocol::evm::{Amount, PaymentQuote, RewardsAddress};
    use self_encryption::XorName as SeXorName;
    use std::time::{Duration, SystemTime};

    fn listing() -> Listing {
        Listing {
            address: [3; 32],
            flags: Flags {
                shown: ShownFields::ALL.without(PaymentField::BlockTimestamp),
                in_index: true,
                withheld: false,
            },
            metadata: Metadata {
                content_type: Some("application/pdf".into()),
                name: Some("report.pdf".into()),
            },
            size: Some(1234),
            payment: ListingPayment {
                tx_hash: Some([7; 32]),
                block_number: Some(42),
                block_timestamp: None,
                log_index: Some(2),
                quote: Some(vec![1, 2, 3]),
            },
            first_seen: Some(1_789_999_200),
        }
    }

    /// A listing as large as a node can record: the longest metadata, every
    /// field shown, and a quote whose every byte takes the most room
    /// msgpack-encoded.
    fn largest_listing() -> Listing {
        let quote = PaymentQuote {
            content: SeXorName([0xff; 32]),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) * 4),
            price: Amount::MAX,
            rewards_address: RewardsAddress::new([0xff; 20]),
            // ML-DSA-65 key and signature sizes.
            pub_key: vec![0xff; 1_952],
            signature: vec![0xff; 3_309],
            committed_key_count: u32::MAX,
            commitment_pin: Some([0xff; 32]),
        };
        Listing {
            address: [0xff; 32],
            flags: Flags {
                shown: ShownFields::ALL,
                in_index: true,
                withheld: false,
            },
            metadata: Metadata {
                content_type: Some(format!("a/{}", "b".repeat(MAX_CONTENT_TYPE_LEN - 2))),
                name: Some("é".repeat(MAX_NAME_LEN / 2)),
            },
            size: Some(u64::MAX),
            payment: ListingPayment {
                tx_hash: Some([0xff; 32]),
                block_number: Some(u64::MAX),
                block_timestamp: Some(u64::MAX),
                log_index: Some(u64::MAX),
                quote: Some(rmp_serde::to_vec(&quote).unwrap()),
            },
            first_seen: None,
        }
    }

    #[test]
    fn the_topic_is_version_2() {
        assert_eq!(TOPIC, "listings.v2");
    }

    #[test]
    fn every_message_round_trips() {
        let mut hidden = listing();
        hidden.flags.shown = ShownFields::NONE;
        hidden.flags.withheld = true;
        hidden.size = None;
        hidden.payment = ListingPayment::default();
        let bodies = vec![
            ListingsBody::ListRequest {
                from: ListingKey::MIN,
                limit: 10,
            },
            ListingsBody::ListRequest {
                from: listing().key().next(),
                limit: MAX_LIST_LIMIT,
            },
            ListingsBody::ListResponse {
                listings: vec![listing(), hidden.clone(), largest_listing()],
                more: true,
            },
            ListingsBody::ListResponse {
                listings: Vec::new(),
                more: false,
            },
            ListingsBody::GetRequest { address: [3; 32] },
            ListingsBody::GetResponse {
                listing: Some(listing()),
            },
            ListingsBody::GetResponse {
                listing: Some(hidden),
            },
            ListingsBody::GetResponse { listing: None },
            ListingsBody::Error {
                message: "busy".into(),
            },
        ];
        for (request_id, body) in bodies.into_iter().enumerate() {
            let message = ListingsMessage {
                request_id: request_id as u64,
                body,
            };
            assert_eq!(
                ListingsMessage::decode(&message.encode().unwrap()),
                Ok(message)
            );
        }
    }

    #[test]
    fn variant_numbers_are_fixed() {
        // The first byte after the request id is the variant's position.
        let first_byte_after_id = |body: ListingsBody| {
            ListingsMessage {
                request_id: 0,
                body,
            }
            .encode()
            .unwrap()[1]
        };
        assert_eq!(
            first_byte_after_id(ListingsBody::ListRequest {
                from: ListingKey::MIN,
                limit: 1
            }),
            0
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::ListResponse {
                listings: Vec::new(),
                more: false
            }),
            1
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::GetRequest { address: [0; 32] }),
            2
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::GetResponse { listing: None }),
            3
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::Error {
                message: String::new()
            }),
            4
        );
    }

    #[test]
    fn a_full_page_of_the_largest_listings_fits() {
        let largest = largest_listing();
        assert!(largest.validate().is_ok());
        let message = ListingsMessage {
            request_id: u64::MAX,
            body: ListingsBody::ListResponse {
                listings: vec![largest; MAX_LIST_LIMIT as usize],
                more: true,
            },
        };
        // About 2.9 MB of the 5 MiB limit. Real keys and signatures encode
        // smaller: only their bytes over 127 take two bytes each.
        let size = message.encode().unwrap().len();
        assert!(size < MAX_WIRE_MESSAGE_SIZE * 6 / 10, "{size} bytes");
    }

    /// A listing in the index showing everything, with this key.
    fn indexed(key: ListingKey) -> Listing {
        Listing {
            address: key.address,
            flags: Flags::V1,
            metadata: Metadata::default(),
            size: None,
            payment: ListingPayment {
                tx_hash: Some([7; 32]),
                block_number: Some(key.block_number),
                block_timestamp: Some(key.time),
                log_index: Some(key.log_index),
                quote: Some(vec![1]),
            },
            first_seen: None,
        }
    }

    fn key(time: u64, last: u8) -> ListingKey {
        let mut address = [0; 32];
        address[31] = last;
        ListingKey {
            time,
            block_number: time,
            log_index: 0,
            address,
        }
    }

    #[test]
    fn checks_list_pages() {
        let page: Vec<Listing> = [key(10, 1), key(10, 2), key(20, 0)]
            .into_iter()
            .map(indexed)
            .collect();
        let next = key(20, 1);
        for limit in [3, 10, MAX_LIST_LIMIT, u32::MAX] {
            assert_eq!(
                check_list_page(ListingKey::MIN, limit, &page, true),
                Ok(Some(next))
            );
            assert_eq!(
                check_list_page(ListingKey::MIN, limit, &page, false),
                Ok(None)
            );
        }
        // From exactly the first key, as the next page asks.
        assert_eq!(check_list_page(key(10, 1), 3, &page, true), Ok(Some(next)));
        assert_eq!(check_list_page(ListingKey::MIN, 3, &[], false), Ok(None));
        // An empty page can't move on, whatever the node says.
        assert_eq!(check_list_page(ListingKey::MIN, 3, &[], true), Ok(None));
        // Hidden times sort by first_seen, and still check out.
        let mut first_seen = indexed(key(30, 0));
        first_seen.flags.shown = ShownFields::NONE;
        first_seen.payment = ListingPayment::default();
        first_seen.first_seen = Some(3_600);
        assert_eq!(
            check_list_page(ListingKey::MIN, 1, &[first_seen.clone()], true),
            Ok(first_seen.key().checked_next())
        );
    }

    #[test]
    fn rejects_bad_list_pages() {
        let page: Vec<Listing> = [key(10, 1), key(10, 2), key(20, 0)]
            .into_iter()
            .map(indexed)
            .collect();
        let check = |listings: &[Listing]| check_list_page(ListingKey::MIN, 10, listings, true);

        assert_eq!(
            check_list_page(ListingKey::MIN, 2, &page, true),
            Err(PageError::TooMany { count: 3, max: 2 })
        );
        let full: Vec<Listing> = (0..=MAX_LIST_LIMIT)
            .map(|i| indexed(key(u64::from(i), 0)))
            .collect();
        assert_eq!(
            check_list_page(ListingKey::MIN, u32::MAX, &full, true),
            Err(PageError::TooMany {
                count: 257,
                max: 256
            })
        );
        assert!(check_list_page(ListingKey::MIN, u32::MAX, &full[1..], true).is_ok());

        let mut outside = page.clone();
        outside[1].flags.in_index = false;
        assert_eq!(check(&outside), Err(PageError::NotInIndex));

        // Outside the index and malformed: refused either way.
        let mut hidden = page.clone();
        hidden[0].flags.in_index = false;
        hidden[0].payment.log_index = None;
        assert_eq!(check(&hidden), Err(PageError::NotInIndex));

        assert_eq!(
            check_list_page(key(10, 2), 10, &page, true),
            Err(PageError::BeforeFrom)
        );

        let mut swapped = page.clone();
        swapped.swap(0, 2);
        assert_eq!(check(&swapped), Err(PageError::OutOfOrder));
        let repeated = [page[0].clone(), page[0].clone()];
        assert_eq!(check(&repeated), Err(PageError::OutOfOrder));
    }

    #[test]
    fn an_invalid_listing_does_not_stop_paging() {
        let page: Vec<Listing> = [key(10, 1), key(10, 2), key(20, 0)]
            .into_iter()
            .map(indexed)
            .collect();
        let next = key(20, 1);
        // Each listing in turn fails validate(): the page still says where
        // the next one starts, and merging leaves the bad listing out.
        for bad in 0..page.len() {
            let mut listings = page.clone();
            listings[bad].payment.quote = None;
            assert!(listings[bad].validate().is_err());
            assert_eq!(
                check_list_page(ListingKey::MIN, 10, &listings, true),
                Ok(Some(next)),
                "listing {bad} invalid"
            );
            let merged = crate::merge_copies(listings.into_iter().map(|listing| (1, listing)));
            assert_eq!(merged.len(), page.len() - 1);
        }
        // So does a listing a later version's rules might refuse, such as a
        // name only version 1 allows, carried over from a version 1 store.
        let mut carried = page.clone();
        carried[1].metadata.name = Some("..".into());
        assert_eq!(carried[1].validate(), Ok(()));
        assert_eq!(
            check_list_page(ListingKey::MIN, 10, &carried, true),
            Ok(Some(next))
        );
    }

    /// Walk a node's index as a client does, `limit` at a time, taking at
    /// most `max_pages` pages. `node` answers each request. Gives the
    /// listings collected and the number of pages, or the first page
    /// refused.
    fn walk(
        limit: u32,
        max_pages: usize,
        mut node: impl FnMut(ListingKey, u32) -> (Vec<Listing>, bool),
    ) -> Result<(Vec<Listing>, usize), PageError> {
        let mut collected = Vec::new();
        let mut from = Some(ListingKey::MIN);
        let mut pages = 0;
        while let Some(key) = from.filter(|_| pages < max_pages) {
            let (listings, more) = node(key, limit);
            pages += 1;
            from = check_list_page(key, limit, &listings, more)?;
            collected.extend(listings);
        }
        Ok((collected, pages))
    }

    #[test]
    fn short_and_endless_pages_end_or_are_refused() {
        let held: Vec<Listing> = (0..10).map(|i| indexed(key(10 * i + 10, 0))).collect();
        // An honest node: the listings from `from` on, at most `limit`.
        let honest = |page_size: usize| {
            let held = held.clone();
            move |from: ListingKey, limit: u32| {
                let rest: Vec<Listing> = held
                    .iter()
                    .filter(|listing| listing.key() >= from)
                    .cloned()
                    .collect();
                let take = page_size.min(limit as usize).min(rest.len());
                (rest[..take].to_vec(), rest.len() > take)
            }
        };
        assert_eq!(walk(256, 100, honest(256)), Ok((held.clone(), 1)));
        assert_eq!(walk(3, 100, honest(256)), Ok((held.clone(), 4)));
        // Pages shorter than asked for, saying there is more: the walk goes
        // on, a listing at a time, and still ends.
        assert_eq!(walk(256, 100, honest(1)), Ok((held.clone(), 10)));

        // A short page that says there is no more ends the walk: the node
        // chooses what it serves.
        let (partial, pages) = walk(256, 100, |_, _| (held[..3].to_vec(), false)).unwrap();
        assert_eq!((partial.len(), pages), (3, 1));

        // Always "more", with nothing in it: one page, then done.
        assert_eq!(
            walk(256, 100, |_, _| (Vec::new(), true)),
            Ok((Vec::new(), 1))
        );

        // The same page again: refused, as it comes before where the client
        // asked from.
        let first_page = held[..2].to_vec();
        assert_eq!(
            walk(2, 100, |_, _| (first_page.clone(), true)),
            Err(PageError::BeforeFrom)
        );

        // New listings without end, each after the last: every page moves
        // on, so only the client's cap stops it.
        let mut minted = 0;
        let endless = |from: ListingKey, limit: u32| {
            let listings: Vec<Listing> = (0..u64::from(limit))
                .map(|i| indexed(key(from.time + i + 1, 0)))
                .collect();
            minted += listings.len();
            (listings, true)
        };
        let (taken, pages) = walk(4, 25, endless).unwrap();
        assert_eq!((taken.len(), pages, minted), (100, 25, 100));
        assert!(taken.windows(2).all(|pair| pair[0].key() < pair[1].key()));
    }

    #[test]
    fn checks_get_responses() {
        let asked = listing().address;
        assert_eq!(check_get_response(&asked, None), Ok(None));
        assert_eq!(
            check_get_response(&asked, Some(listing())),
            Ok(Some(listing()))
        );
        // Another file's listing, genuine as it may be, is not an answer.
        let mut other = listing();
        other.address[0] ^= 1;
        assert_eq!(other.validate(), Ok(()));
        assert_eq!(
            check_get_response(&asked, Some(other.clone())),
            Err(PageError::WrongAddress)
        );
        assert_eq!(
            check_get_response(&other.address, Some(other.clone())),
            Ok(Some(other))
        );
        // Nor is a malformed one.
        let mut malformed = listing();
        malformed.first_seen = None;
        assert_eq!(
            check_get_response(&asked, Some(malformed)),
            Err(PageError::Malformed(ListingError::MissingFirstSeen))
        );
        // A listing outside the index is a fine answer.
        let mut outside = listing();
        outside.flags.in_index = false;
        outside.first_seen = None;
        assert_eq!(
            check_get_response(&asked, Some(outside.clone())),
            Ok(Some(outside))
        );
    }

    #[test]
    fn paging_stops_at_the_largest_key() {
        let largest = ListingKey {
            time: u64::MAX,
            block_number: u64::MAX,
            log_index: u64::MAX,
            address: [0xff; 32],
        };
        assert_eq!(largest.checked_next(), None);
        let page = [indexed(largest)];
        // A node can't keep a client asking for the same page.
        assert_eq!(check_list_page(largest, 1, &page, true), Ok(None));
        assert_eq!(check_list_page(ListingKey::MIN, 1, &page, true), Ok(None));
    }

    #[test]
    fn rejects_pages_over_the_limit() {
        let minimal = Listing {
            address: [0; 32],
            flags: Flags::from_byte(0).unwrap(),
            metadata: Metadata::default(),
            size: None,
            payment: ListingPayment::default(),
            first_seen: None,
        };
        let page = |count: u32| ListingsMessage {
            request_id: 1,
            body: ListingsBody::ListResponse {
                listings: vec![minimal.clone(); count as usize],
                more: false,
            },
        };
        let full = page(MAX_LIST_LIMIT);
        assert_eq!(ListingsMessage::decode(&full.encode().unwrap()), Ok(full));

        let over = page(MAX_LIST_LIMIT + 1);
        assert!(matches!(over.encode(), Err(MessageError::Encode(_))));
        // Sent anyway, it is refused on arrival, however small it is.
        for count in [MAX_LIST_LIMIT + 1, 100_000] {
            let bytes = postcard::to_stdvec(&page(count)).unwrap();
            assert!(bytes.len() < MAX_WIRE_MESSAGE_SIZE);
            assert!(matches!(
                ListingsMessage::decode(&bytes),
                Err(MessageError::Decode(_))
            ));
        }
    }

    #[test]
    fn wire_layout_is_fixed() {
        let hex = |hex: &str| crate::proof::decode_hex(hex).unwrap();

        // A list request: the key as three varints and 32 raw bytes, not its
        // 56-byte store form.
        let request = ListingsMessage {
            request_id: 7,
            body: ListingsBody::ListRequest {
                from: ListingKey {
                    time: 1_790_000_000,
                    block_number: 300,
                    log_index: 7,
                    address: [0xab; 32],
                },
                limit: 256,
            },
        };
        let expected = hex(concat!(
            "07",         // request id
            "00",         // ListRequest
            "80f7c4d506", // time
            "ac02",       // block number
            "07",         // log index
            "abababababababababababababababababababababababababababababababab",
            "8002", // limit
        ));
        assert_eq!(request.encode().unwrap(), expected);
        assert_eq!(ListingsMessage::decode(&expected), Ok(request));

        // A listing showing everything.
        let shown = ListingsMessage {
            request_id: 300,
            body: ListingsBody::GetResponse {
                listing: Some(Listing {
                    address: [0x11; 32],
                    flags: Flags::V1,
                    metadata: Metadata {
                        content_type: Some("text/plain".into()),
                        name: Some("a.txt".into()),
                    },
                    size: Some(20_480),
                    payment: ListingPayment {
                        tx_hash: Some([0x22; 32]),
                        block_number: Some(70_000_001),
                        block_timestamp: Some(1_790_000_000),
                        log_index: Some(7),
                        quote: Some(vec![0x93, 1, 2, 3]),
                    },
                    first_seen: None,
                }),
            },
        };
        let expected = hex(concat!(
            "ac02", // request id
            "03",   // GetResponse
            "01",   // Some
            "1111111111111111111111111111111111111111111111111111111111111111",
            "3f",                       // flags
            "010a746578742f706c61696e", // content type
            "0105612e747874",           // name
            "0180a001",                 // size
            "01",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0181bbb021",   // block number
            "0180f7c4d506", // block timestamp
            "0107",         // log index
            "010493010203", // quote
            "00",           // first_seen
        ));
        assert_eq!(shown.encode().unwrap(), expected);
        assert_eq!(ListingsMessage::decode(&expected), Ok(shown));

        // A listing hiding everything, in the index, its data map withheld.
        let hidden = ListingsMessage {
            request_id: 0,
            body: ListingsBody::GetResponse {
                listing: Some(Listing {
                    address: [0x33; 32],
                    flags: Flags::from_byte(0x60).unwrap(),
                    metadata: Metadata::default(),
                    size: None,
                    payment: ListingPayment::default(),
                    first_seen: Some(1_789_999_200),
                }),
            },
        };
        let expected = hex(concat!(
            "00", // request id
            "03", // GetResponse
            "01", // Some
            "3333333333333333333333333333333333333333333333333333333333333333",
            "60",           // flags
            "0000",         // no content type or name
            "00",           // no size
            "0000000000",   // no payment fields
            "01e0f0c4d506", // first_seen
        ));
        assert_eq!(hidden.encode().unwrap(), expected);
        assert_eq!(ListingsMessage::decode(&expected), Ok(hidden));
    }

    #[test]
    fn rejects_garbage() {
        assert!(ListingsMessage::decode(&[0xff; 8]).is_err());
        assert!(matches!(
            ListingsMessage::decode(&vec![0; MAX_WIRE_MESSAGE_SIZE + 1]),
            Err(MessageError::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_listings_with_the_reserved_flag() {
        let message = ListingsMessage {
            request_id: 0,
            body: ListingsBody::GetResponse {
                listing: Some(listing()),
            },
        };
        let mut bytes = message.encode().unwrap();
        // request id, variant, Some, the 32-byte address, then the flags.
        let flags_at = 1 + 1 + 1 + 32;
        assert_eq!(bytes[flags_at], listing().flags.to_byte());
        bytes[flags_at] |= Flags::RESERVED;
        assert!(matches!(
            ListingsMessage::decode(&bytes),
            Err(MessageError::Decode(_))
        ));
    }
}
