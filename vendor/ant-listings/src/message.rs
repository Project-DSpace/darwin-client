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
//!
//! To follow what a node serves in a range of addresses instead, ask for the
//! changes in its change feed ([`ChangesRequest`], checked with
//! [`check_changes_page`]), and read the range afresh ([`RangeListRequest`],
//! checked with [`check_range_page`]) when the node's feed is new to the
//! reader. [`FeedSync`](crate::FeedSync) does both for a mirror of one node.
//! A node that doesn't know a request drops it unanswered.

use crate::feed::{view_hash, AddressRange, DigestEntry, FeedChange, SetHash};
use crate::listing::{Listing, ListingError, ListingKey};
use ant_protocol::{XorName, MAX_WIRE_MESSAGE_SIZE};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// The topic listings messages travel on, separate from the chunk protocol's.
/// Version 2 carries version 2 listings and keys; nothing answers
/// `listings.v1` any more.
pub const TOPIC: &str = "listings.v2";

/// The most listings, changes or digest entries one response carries. A full
/// page of the largest listings stays well under the wire limit.
pub const MAX_LIST_LIMIT: u32 = 256;

/// The most peers a [`ChangesResponse`] lists: a node's nearest peers, as
/// many as a Kademlia bucket holds.
pub const VIEW_PEERS: usize = 20;

/// The most watches ([`ChangesRequest::watch`]) a node keeps at once. Once
/// it has this many it refuses a new one, so a requester that already
/// watches is never pushed out. The requester can't tell, and its next
/// request still finds every change.
pub const MAX_WATCHERS: usize = 4;

/// How long, in seconds, a watch lasts if the watcher asks nothing more of
/// the node: the minute until its next poll, and two minutes more.
pub const WATCH_LEASE: u64 = 180;

/// The request id of a push ([`ChangesRequest::watch`]): the bitwise
/// complement of the id of the request that set the watch. The answer to
/// that request has the request's own id, so a requester tells pushes from
/// the answer by id alone, whichever arrives first: messages can overtake
/// one another on the way. The complement of a push's id is the watching
/// request's. No id a requester uses with a node should be the complement of
/// another it uses with the node, which ids chosen at random almost never
/// are.
#[must_use]
pub const fn push_request_id(request_id: u64) -> u64 {
    !request_id
}

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
    /// The changes to what a node serves in the index in an address range,
    /// after a record of its change feed. See [`ChangesRequest`].
    ChangesRequest(ChangesRequest),
    /// A node's answer to a [`ChangesRequest`], or a push to a watcher. Never
    /// more than [`MAX_LIST_LIMIT`] changes or [`VIEW_PEERS`] peers:
    /// [`ListingsMessage::decode`] refuses more. See [`ChangesResponse`].
    ChangesResponse(ChangesResponse),
    /// The digest entries a node serves in the index in an address range, in
    /// address order. See [`RangeListRequest`].
    RangeListRequest(RangeListRequest),
    /// A node's answer to a [`RangeListRequest`]. Never more than
    /// [`MAX_LIST_LIMIT`] entries: [`ListingsMessage::decode`] refuses more.
    /// See [`RangeListResponse`].
    RangeListResponse(RangeListResponse),
}

/// A [`ListingsBody::ChangesRequest`]: the changes to what a node serves in
/// the index in an address range, after a record of its change feed (see
/// [`feed`](crate::feed)).
///
/// The node answers with a [`ChangesResponse`]. If `epoch` is not its feed's,
/// or `after` is beyond its head, it sends no changes, only where its feed
/// stands: read the range afresh with [`RangeListRequest`]s, then follow the
/// feed from that head. Otherwise it sends the records in the range after
/// `after`, in order, at most `limit` and never more than [`MAX_LIST_LIMIT`].
/// It may stop sooner, once it has read as many records as it reads for one
/// request, and says where it stopped. Check the answer with
/// [`check_changes_page`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesRequest {
    /// The epoch `after` counts in, from the node's last answer. 0, which no
    /// node uses, for none yet.
    pub epoch: u64,
    /// The number of the last record already seen: changes after it are
    /// wanted.
    pub after: u64,
    /// The range's prefix. Its bits after the first `bits` don't matter.
    pub prefix: XorName,
    /// How many leading bits of `prefix` the range fixes (see
    /// [`AddressRange`]).
    pub bits: u8,
    /// The most changes wanted.
    pub limit: u32,
    /// Whether to list the node's nearest peers in the answer's `peers`.
    pub want_peers: bool,
    /// Whether to be sent the range's new records as the node makes them.
    /// The node sends each new record in the range as a [`ChangesResponse`]
    /// whose request id is [`push_request_id`] of this request's: a push. A
    /// push can arrive before this request's answer; the id tells them
    /// apart. The watch lasts until the requester's next `ChangesRequest` to
    /// the node, which sets a new one if it asks for one, or [`WATCH_LEASE`]
    /// seconds if none comes. A node keeps at most [`MAX_WATCHERS`] watches.
    /// A missed push is caught by the next request, so pushes are never
    /// acknowledged. Check each with [`check_push`].
    pub watch: bool,
}

impl ChangesRequest {
    /// The address range asked about.
    #[must_use]
    pub fn range(&self) -> AddressRange {
        AddressRange::new(self.prefix, self.bits)
    }
}

/// A [`ListingsBody::ChangesResponse`]: a node's answer to a
/// [`ChangesRequest`], or a push to a watcher.
///
/// `count` and `set_hash` describe everything the node serves in the range at
/// `head`, so a reader whose mirror has reached `head` can check it.
///
/// A push carries new records, with `next` equal to `head`, `more` false and
/// no peers. Its request id is [`push_request_id`] of the id of the request
/// that set the watch, while the answer to that request has the request's
/// own: a requester tells them apart by id alone, in whatever order they
/// arrive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesResponse {
    /// The node's epoch: random, never 0, and new whenever the node numbers
    /// its records afresh.
    pub epoch: u64,
    /// The number of the node's latest record, 0 if it has none.
    pub head: u64,
    /// Where the answer stops: the number of the last record the node read
    /// for it, which the next request asks after. `head` once it has read to
    /// the end.
    pub next: u64,
    /// How many entries the node serves in the range, at `head`.
    pub count: u64,
    /// Their [`SetHash`].
    pub set_hash: SetHash,
    /// The records in the range after the request's `after`, up to `next`, in
    /// order: one per address, the latest change to it.
    pub changes: Vec<FeedChange>,
    /// Whether the node has records after `next`: exactly when `next` is
    /// before `head`.
    pub more: bool,
    /// [`view_hash`] of the node's nearest peers.
    pub view: [u8; 32],
    /// Those peers' ids, at most [`VIEW_PEERS`], when the request asked for
    /// them; otherwise none.
    pub peers: Vec<[u8; 32]>,
}

/// A [`ListingsBody::RangeListRequest`]: the digest entries a node serves in
/// the index in an address range, in address order, after an address. For
/// reading a range afresh. Check the answer with [`check_range_page`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeListRequest {
    /// The range's prefix. Its bits after the first `bits` don't matter.
    pub prefix: XorName,
    /// How many leading bits of `prefix` the range fixes (see
    /// [`AddressRange`]).
    pub bits: u8,
    /// The last address already seen: entries after it are wanted. `None`
    /// for the range's start.
    pub after: Option<XorName>,
    /// The most entries wanted.
    pub limit: u32,
}

impl RangeListRequest {
    /// The address range asked about.
    #[must_use]
    pub fn range(&self) -> AddressRange {
        AddressRange::new(self.prefix, self.bits)
    }
}

/// A [`ListingsBody::RangeListResponse`]: digest entries in address order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeListResponse {
    /// The entries, at most the request's `limit` and never more than
    /// [`MAX_LIST_LIMIT`].
    pub entries: Vec<DigestEntry>,
    /// Whether the node serves entries in the range after the last one
    /// returned.
    pub more: bool,
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

/// Why a [`ChangesResponse`] or [`RangeListResponse`] is not a valid answer
/// to its request, or a [`ChangesResponse`] not a valid push.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FeedError {
    /// More changes or entries than were asked for, or than
    /// [`MAX_LIST_LIMIT`].
    #[error("the answer has {count} records, more than {max}")]
    TooMany {
        /// How many the answer has.
        count: usize,
        /// The most it may have.
        max: usize,
    },
    /// More peers than [`VIEW_PEERS`].
    #[error("the answer lists {count} peers, more than {max}")]
    TooManyPeers {
        /// How many it lists.
        count: usize,
        /// The most it may list.
        max: usize,
    },
    /// Peers listed when the request didn't ask for them, or in a push.
    #[error("the answer lists peers it wasn't asked for")]
    UnaskedPeers,
    /// The peers listed don't hash to the answer's `view`.
    #[error("the peers listed don't match the view")]
    WrongView,
    /// The node gives epoch 0, which no node uses.
    #[error("the node gives epoch 0")]
    NoEpoch,
    /// An answer saying the node's feed is not the one the request followed
    /// carries changes, or doesn't stop at its head.
    #[error("an answer from another feed has changes or doesn't stop at its head")]
    BadRestart,
    /// `next` is before the request's `after` or after `head`, `more`
    /// doesn't say whether `next` is before `head`, or the answer says there
    /// is more without moving on.
    #[error("the answer's next, head and more don't fit together or with the request")]
    BadNext,
    /// A change's number is not after the request's `after` and the change
    /// before it, or is after `next`.
    #[error("the changes are not in order within the records the answer covers")]
    OutOfSequence,
    /// An address outside the range asked about.
    #[error("the answer has an address outside the range asked about")]
    OutOfRange,
    /// Two records for one address.
    #[error("the answer has two records for one address")]
    RepeatedAddress,
    /// Entries not after the address asked after, or not in strictly
    /// increasing address order.
    #[error("the entries are not in address order after the one asked after")]
    OutOfOrder,
}

/// What a valid [`ChangesResponse`] says, from [`check_changes_page`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangesPage {
    /// The changes follow on from the request's `after`: apply them in
    /// order. `Some(next)` if the node has more records: ask again after
    /// `next`. `None` once they reach its head.
    Follows(Option<u64>),
    /// The node's feed is not the one the request followed: it has another
    /// epoch, or its head is before the request's `after`. Read the range
    /// afresh with [`RangeListRequest`]s, then follow the feed after `head`
    /// in `epoch`.
    Restart {
        /// The node's epoch.
        epoch: u64,
        /// The node's head.
        head: u64,
    },
}

/// Check a node's answer to a [`ChangesRequest`], and say what it means.
///
/// The answer must give an epoch other than 0, list peers only if asked for
/// and then those its `view` hashes, and either:
///
/// - say that its feed is not the one the request followed (another epoch,
///   or a head before `after`), with no changes, `next` at `head` and `more`
///   false: [`ChangesPage::Restart`]; or
/// - carry at most `min(limit, MAX_LIST_LIMIT)` changes in the range asked
///   about, one per address, numbered in increasing order after `after` and
///   up to `next`, where `next` lies from `after` to `head`, `more` says
///   whether `next` is before `head`, and an answer with `more` moves past
///   `after`: [`ChangesPage::Follows`].
///
/// As with [`check_list_page`], only the answer's shape is checked: each
/// answer with more moves strictly on, so paging a feed ends unless the node
/// keeps making records, which [`FeedSync`](crate::FeedSync)'s allowances
/// stop. Whether each entry describes a valid listing is left to the reader.
///
/// # Errors
///
/// Returns the first problem found. Drop the whole answer.
pub fn check_changes_page(
    request: &ChangesRequest,
    response: &ChangesResponse,
) -> Result<ChangesPage, FeedError> {
    check_peers(request.want_peers, response)?;
    if response.epoch == 0 {
        return Err(FeedError::NoEpoch);
    }
    if response.epoch != request.epoch || response.head < request.after {
        if !response.changes.is_empty() || response.more || response.next != response.head {
            return Err(FeedError::BadRestart);
        }
        return Ok(ChangesPage::Restart {
            epoch: response.epoch,
            head: response.head,
        });
    }
    if response.next < request.after
        || response.next > response.head
        || response.more != (response.next < response.head)
        || (response.more && response.next == request.after)
    {
        return Err(FeedError::BadNext);
    }
    check_changes(
        request.range(),
        request.limit,
        request.after,
        response.next,
        &response.changes,
    )?;
    Ok(ChangesPage::Follows(response.more.then_some(response.next)))
}

/// Check a push: a [`ChangesResponse`] a node sent for a watch on `range`
/// ([`ChangesRequest::watch`]), with [`push_request_id`] of the watching
/// request's id. It must give an epoch other than 0, have `next` at `head`,
/// `more` false and no peers, and carry at most [`MAX_LIST_LIMIT`] changes
/// in `range`, one per address, numbered in increasing order up to `head`.
///
/// # Errors
///
/// Returns the first problem found. Drop the push.
pub fn check_push(range: AddressRange, push: &ChangesResponse) -> Result<(), FeedError> {
    if !push.peers.is_empty() {
        return Err(FeedError::UnaskedPeers);
    }
    if push.epoch == 0 {
        return Err(FeedError::NoEpoch);
    }
    if push.more || push.next != push.head {
        return Err(FeedError::BadNext);
    }
    check_changes(range, MAX_LIST_LIMIT, 0, push.head, &push.changes)
}

/// Check a node's answer to a [`RangeListRequest`], and say where the next
/// request starts.
///
/// The answer must have at most `min(limit, MAX_LIST_LIMIT)` entries, each in
/// the range asked about, after the address asked after, in strictly
/// increasing address order. Returns the `after` of the next request: the
/// last entry's address, when the node said it has `more` and the answer
/// moved on. `None` means the node has no more in the range to give: it said
/// so, the answer was empty, or the last address was the range's last.
///
/// # Errors
///
/// Returns the first problem found. Drop the whole answer.
pub fn check_range_page(
    request: &RangeListRequest,
    response: &RangeListResponse,
) -> Result<Option<XorName>, FeedError> {
    let range = request.range();
    let max = usize::try_from(request.limit.min(MAX_LIST_LIMIT)).unwrap_or(usize::MAX);
    if response.entries.len() > max {
        return Err(FeedError::TooMany {
            count: response.entries.len(),
            max,
        });
    }
    let mut last = request.after;
    for entry in &response.entries {
        if !range.contains(&entry.address) {
            return Err(FeedError::OutOfRange);
        }
        if last.is_some_and(|last| entry.address <= last) {
            return Err(FeedError::OutOfOrder);
        }
        last = Some(entry.address);
    }
    Ok(response
        .entries
        .last()
        .map(|entry| entry.address)
        .filter(|address| response.more && *address != range.last()))
}

/// Check `changes`, an answer's or push's: at most `min(limit,
/// MAX_LIST_LIMIT)`, each in `range`, one per address, numbered in
/// increasing order after `after` and up to `next`.
fn check_changes(
    range: AddressRange,
    limit: u32,
    after: u64,
    next: u64,
    changes: &[FeedChange],
) -> Result<(), FeedError> {
    let max = usize::try_from(limit.min(MAX_LIST_LIMIT)).unwrap_or(usize::MAX);
    if changes.len() > max {
        return Err(FeedError::TooMany {
            count: changes.len(),
            max,
        });
    }
    let mut last = after;
    let mut addresses = HashSet::with_capacity(changes.len());
    for change in changes {
        let seq = change.seq();
        if seq <= last || seq > next {
            return Err(FeedError::OutOfSequence);
        }
        last = seq;
        let address = change.address();
        if !range.contains(&address) {
            return Err(FeedError::OutOfRange);
        }
        if !addresses.insert(address) {
            return Err(FeedError::RepeatedAddress);
        }
    }
    Ok(())
}

/// Check an answer's peers: at most [`VIEW_PEERS`]; none unless asked for,
/// and then those its `view` hashes.
fn check_peers(asked: bool, response: &ChangesResponse) -> Result<(), FeedError> {
    if response.peers.len() > VIEW_PEERS {
        return Err(FeedError::TooManyPeers {
            count: response.peers.len(),
            max: VIEW_PEERS,
        });
    }
    if !asked {
        return if response.peers.is_empty() {
            Ok(())
        } else {
            Err(FeedError::UnaskedPeers)
        };
    }
    if view_hash(&response.peers) != response.view {
        return Err(FeedError::WrongView);
    }
    Ok(())
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
    /// What a response has more of than the protocol allows, if anything:
    /// how many, the most allowed, and of what.
    fn over_limit(&self) -> Option<(usize, usize, &'static str)> {
        let page = usize::try_from(MAX_LIST_LIMIT).unwrap_or(usize::MAX);
        let (count, max, what) = match self {
            Self::ListResponse { listings, .. } => (listings.len(), page, "listings"),
            Self::ChangesResponse(response) if response.peers.len() > VIEW_PEERS => {
                (response.peers.len(), VIEW_PEERS, "peers")
            }
            Self::ChangesResponse(response) => (response.changes.len(), page, "changes"),
            Self::RangeListResponse(response) => (response.entries.len(), page, "entries"),
            _ => return None,
        };
        (count > max).then_some((count, max, what))
    }
}

impl ListingsMessage {
    /// Encode for sending.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails, the result exceeds the wire limit,
    /// or it is a response with more than [`MAX_LIST_LIMIT`] listings,
    /// changes or entries, or more than [`VIEW_PEERS`] peers.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        if let Some((count, max, what)) = self.body.over_limit() {
            return Err(MessageError::Encode(format!(
                "{count} {what} in one response, more than {max}"
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

    /// Decode received bytes. Bytes after a whole message are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes exceed the wire limit, are not a valid
    /// message, or are a response with more than [`MAX_LIST_LIMIT`]
    /// listings, changes or entries, or more than [`VIEW_PEERS`] peers.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(MessageError::TooLarge {
                size: bytes.len(),
                max: MAX_WIRE_MESSAGE_SIZE,
            });
        }
        let message: Self =
            postcard::from_bytes(bytes).map_err(|e| MessageError::Decode(e.to_string()))?;
        if let Some((count, max, what)) = message.body.over_limit() {
            return Err(MessageError::Decode(format!(
                "{count} {what} in one response, more than {max}"
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

    /// An address starting `first` and ending `last`.
    fn address(first: u8, last: u8) -> XorName {
        let mut address = [0; 32];
        address[0] = first;
        address[31] = last;
        address
    }

    /// The `n`th of many addresses in the upper half of the space.
    fn nth_upper(n: usize) -> XorName {
        let mut address = [0x80; 32];
        address[28..].copy_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
        address
    }

    fn feed_entry(address: XorName) -> DigestEntry {
        DigestEntry {
            address,
            time: 1_790_000_000,
            block_number: 70_000_001,
            log_index: 0,
            first_seen: None,
            digest: [9; 32],
        }
    }

    fn entry_at(seq: u64, address: XorName) -> FeedChange {
        FeedChange::Entry {
            seq,
            entry: feed_entry(address),
        }
    }

    fn removed_at(seq: u64, address: XorName) -> FeedChange {
        FeedChange::Removed { seq, address }
    }

    /// A request for the changes after `after` in the upper half of the
    /// address space, in epoch 77.
    fn changes_request(after: u64) -> ChangesRequest {
        ChangesRequest {
            epoch: 77,
            after,
            prefix: [0x80; 32],
            bits: 1,
            limit: 10,
            want_peers: false,
            watch: false,
        }
    }

    /// An answer in epoch 77, with `more` as `next` and `head` say.
    fn changes_response(head: u64, next: u64, changes: Vec<FeedChange>) -> ChangesResponse {
        ChangesResponse {
            epoch: 77,
            head,
            next,
            count: 3,
            set_hash: SetHash::EMPTY,
            changes,
            more: next < head,
            view: [6; 32],
            peers: Vec::new(),
        }
    }

    /// An answer saying the feed is not the one asked about.
    fn restart(epoch: u64, head: u64) -> ChangesResponse {
        ChangesResponse {
            epoch,
            ..changes_response(head, head, Vec::new())
        }
    }

    fn range_request(after: Option<XorName>, limit: u32) -> RangeListRequest {
        RangeListRequest {
            prefix: [0x80; 32],
            bits: 1,
            after,
            limit,
        }
    }

    /// The entry for the listing showing everything in
    /// [`wire_layout_is_fixed`].
    fn shown_entry() -> DigestEntry {
        DigestEntry {
            address: [0x11; 32],
            time: 1_790_000_000,
            block_number: 70_000_001,
            log_index: 7,
            first_seen: None,
            digest: crate::proof::decode_hex(
                "ff7382a741884769cfe1ed0093aaff1fe383981a87b6cd3e04128a6eb1d0a087",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        }
    }

    /// One of each message, the feed's included.
    fn one_of_each() -> Vec<ListingsMessage> {
        let peers = vec![[1; 32], [2; 32]];
        let bodies = vec![
            ListingsBody::ListRequest {
                from: ListingKey::MIN,
                limit: 10,
            },
            ListingsBody::ListResponse {
                listings: vec![listing(), largest_listing()],
                more: true,
            },
            ListingsBody::GetRequest { address: [3; 32] },
            ListingsBody::GetResponse {
                listing: Some(listing()),
            },
            ListingsBody::Error {
                message: "busy".into(),
            },
            ListingsBody::ChangesRequest(changes_request(5)),
            ListingsBody::ChangesRequest(ChangesRequest {
                epoch: 0,
                after: 0,
                prefix: [0; 32],
                bits: 0,
                limit: MAX_LIST_LIMIT,
                want_peers: true,
                watch: true,
            }),
            ListingsBody::ChangesResponse(changes_response(
                20,
                12,
                vec![
                    entry_at(6, address(0x81, 1)),
                    removed_at(12, address(0x90, 2)),
                ],
            )),
            ListingsBody::ChangesResponse(ChangesResponse {
                view: view_hash(&peers),
                peers,
                ..restart(78, 0)
            }),
            ListingsBody::RangeListRequest(range_request(None, 256)),
            ListingsBody::RangeListRequest(range_request(Some(address(0x81, 1)), 1)),
            ListingsBody::RangeListResponse(RangeListResponse {
                entries: vec![feed_entry(address(0x81, 1)), shown_entry()],
                more: true,
            }),
            ListingsBody::RangeListResponse(RangeListResponse {
                entries: Vec::new(),
                more: false,
            }),
        ];
        bodies
            .into_iter()
            .zip(0..)
            .map(|(body, request_id)| ListingsMessage { request_id, body })
            .collect()
    }

    #[test]
    fn every_feed_message_round_trips() {
        for message in one_of_each() {
            assert_eq!(
                ListingsMessage::decode(&message.encode().unwrap()),
                Ok(message)
            );
        }
    }

    #[test]
    fn feed_variant_numbers_are_fixed() {
        // After Error (4), in the order they were added.
        let first_byte_after_id = |body: ListingsBody| {
            ListingsMessage {
                request_id: 0,
                body,
            }
            .encode()
            .unwrap()[1]
        };
        assert_eq!(
            first_byte_after_id(ListingsBody::ChangesRequest(changes_request(0))),
            5
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::ChangesResponse(restart(1, 0))),
            6
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::RangeListRequest(range_request(None, 1))),
            7
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::RangeListResponse(RangeListResponse {
                entries: Vec::new(),
                more: false
            })),
            8
        );
    }

    #[test]
    fn feed_wire_layout_is_fixed() {
        let hex = |hex: &str| crate::proof::decode_hex(hex).unwrap();
        let mut prefix = [0; 32];
        prefix[..2].copy_from_slice(&[0xab, 0xc0]);

        let request = ListingsMessage {
            request_id: 7,
            body: ListingsBody::ChangesRequest(ChangesRequest {
                epoch: 258,
                after: 300,
                prefix,
                bits: 12,
                limit: 256,
                want_peers: true,
                watch: false,
            }),
        };
        let expected = hex(concat!(
            "07",   // request id
            "05",   // ChangesRequest
            "8202", // epoch
            "ac02", // after
            "abc0000000000000000000000000000000000000000000000000000000000000",
            "0c",   // bits
            "8002", // limit
            "01",   // want peers
            "00",   // watch
        ));
        assert_eq!(request.encode().unwrap(), expected);
        assert_eq!(ListingsMessage::decode(&expected), Ok(request));

        // A record of each kind, the set hash of the one entry left, and
        // one peer.
        let response = ListingsMessage {
            request_id: 7,
            body: ListingsBody::ChangesResponse(ChangesResponse {
                epoch: 258,
                head: 9,
                next: 9,
                count: 1,
                set_hash: SetHash::of([&shown_entry()]),
                changes: vec![
                    FeedChange::Entry {
                        seq: 8,
                        entry: shown_entry(),
                    },
                    FeedChange::Removed {
                        seq: 9,
                        address: [0x33; 32],
                    },
                ],
                more: false,
                view: [0x66; 32],
                peers: vec![[0x01; 32]],
            }),
        };
        let expected = hex(concat!(
            "07",   // request id
            "06",   // ChangesResponse
            "8202", // epoch
            "09",   // head
            "09",   // next
            "01",   // count
            "19c9d6e39b3939e2b26c4b216f03c40c919efa73b49d7c17390086d224503d53",
            "02", // two changes
            "00", // an entry
            "08", // its number
            "1111111111111111111111111111111111111111111111111111111111111111",
            "80f7c4d506", // time
            "81bbb021",   // block number
            "07",         // log index
            "00",         // no first_seen
            "ff7382a741884769cfe1ed0093aaff1fe383981a87b6cd3e04128a6eb1d0a087",
            "01", // a removal
            "09", // its number
            "3333333333333333333333333333333333333333333333333333333333333333",
            "00", // no more
            "6666666666666666666666666666666666666666666666666666666666666666",
            "01", // one peer
            "0101010101010101010101010101010101010101010101010101010101010101",
        ));
        assert_eq!(response.encode().unwrap(), expected);
        assert_eq!(ListingsMessage::decode(&expected), Ok(response));

        let mut after = prefix;
        after[1] = 0xc5;
        let range = ListingsMessage {
            request_id: 0,
            body: ListingsBody::RangeListRequest(RangeListRequest {
                prefix,
                bits: 12,
                after: Some(after),
                limit: 256,
            }),
        };
        let expected = hex(concat!(
            "00", // request id
            "07", // RangeListRequest
            "abc0000000000000000000000000000000000000000000000000000000000000",
            "0c", // bits
            "01", // after
            "abc5000000000000000000000000000000000000000000000000000000000000",
            "8002", // limit
        ));
        assert_eq!(range.encode().unwrap(), expected);
        assert_eq!(ListingsMessage::decode(&expected), Ok(range));
        let from_start = ListingsMessage {
            request_id: 0,
            body: ListingsBody::RangeListRequest(RangeListRequest {
                prefix,
                bits: 12,
                after: None,
                limit: 1,
            }),
        };
        let expected = hex(concat!(
            "0007",
            "abc0000000000000000000000000000000000000000000000000000000000000",
            "0c",
            "00", // from the range's start
            "01",
        ));
        assert_eq!(from_start.encode().unwrap(), expected);

        // An entry for a listing that hides its time.
        let entries = ListingsMessage {
            request_id: 300,
            body: ListingsBody::RangeListResponse(RangeListResponse {
                entries: vec![DigestEntry {
                    address: [0x33; 32],
                    time: 1_789_999_200,
                    block_number: 0,
                    log_index: 0,
                    first_seen: Some(1_789_999_200),
                    digest: [0x44; 32],
                }],
                more: true,
            }),
        };
        let expected = hex(concat!(
            "ac02", // request id
            "08",   // RangeListResponse
            "01",   // one entry
            "3333333333333333333333333333333333333333333333333333333333333333",
            "e0f0c4d506",   // time: first_seen
            "00",           // block number
            "00",           // log index
            "01e0f0c4d506", // first_seen
            "4444444444444444444444444444444444444444444444444444444444444444",
            "01", // more
        ));
        assert_eq!(entries.encode().unwrap(), expected);
        assert_eq!(ListingsMessage::decode(&expected), Ok(entries));
    }

    #[test]
    fn the_largest_feed_messages_fit() {
        let largest = DigestEntry {
            address: [0xff; 32],
            time: u64::MAX,
            block_number: u64::MAX,
            log_index: u64::MAX,
            first_seen: Some(u64::MAX),
            digest: [0xff; 32],
        };
        let full = MAX_LIST_LIMIT as usize;
        let messages = [
            ListingsBody::ChangesRequest(ChangesRequest {
                epoch: u64::MAX,
                after: u64::MAX,
                prefix: [0xff; 32],
                bits: u8::MAX,
                limit: u32::MAX,
                want_peers: true,
                watch: true,
            }),
            ListingsBody::ChangesResponse(ChangesResponse {
                epoch: u64::MAX,
                head: u64::MAX,
                next: u64::MAX,
                count: u64::MAX,
                set_hash: SetHash::from_bytes([0xff; 32]),
                changes: vec![
                    FeedChange::Entry {
                        seq: u64::MAX,
                        entry: largest,
                    };
                    full
                ],
                more: true,
                view: [0xff; 32],
                peers: vec![[0xff; 32]; VIEW_PEERS],
            }),
            ListingsBody::RangeListRequest(RangeListRequest {
                prefix: [0xff; 32],
                bits: u8::MAX,
                after: Some([0xff; 32]),
                limit: u32::MAX,
            }),
            ListingsBody::RangeListResponse(RangeListResponse {
                entries: vec![largest; full],
                more: true,
            }),
        ];
        for body in messages {
            let message = ListingsMessage {
                request_id: u64::MAX,
                body,
            };
            let bytes = message.encode().unwrap();
            // About 30 KB at most, of the 5 MiB limit: each change takes at
            // most 116 bytes.
            assert!(bytes.len() < 32 * 1024, "{} bytes", bytes.len());
            assert!(bytes.len() < MAX_WIRE_MESSAGE_SIZE);
            assert_eq!(ListingsMessage::decode(&bytes), Ok(message));
        }
    }

    #[test]
    fn feed_answers_over_the_limits_are_refused() {
        let changes = |count: usize| {
            (0..count)
                .map(|n| entry_at(u64::try_from(n).unwrap() + 1, nth_upper(n)))
                .collect::<Vec<_>>()
        };
        let peers = |count: usize| {
            (0..count)
                .map(|n| [u8::try_from(n).unwrap(); 32])
                .collect::<Vec<_>>()
        };
        let answer = |changes: Vec<FeedChange>, peers: Vec<[u8; 32]>| ListingsMessage {
            request_id: 1,
            body: ListingsBody::ChangesResponse(ChangesResponse {
                view: view_hash(&peers),
                peers,
                ..changes_response(1_000, 1_000, changes)
            }),
        };
        let entries = |count: usize| ListingsMessage {
            request_id: 1,
            body: ListingsBody::RangeListResponse(RangeListResponse {
                entries: (0..count).map(|n| feed_entry(nth_upper(n))).collect(),
                more: false,
            }),
        };
        let full = MAX_LIST_LIMIT as usize;
        for fits in [answer(changes(full), peers(VIEW_PEERS)), entries(full)] {
            assert_eq!(ListingsMessage::decode(&fits.encode().unwrap()), Ok(fits));
        }
        for over in [
            answer(changes(full + 1), peers(1)),
            answer(changes(1), peers(VIEW_PEERS + 1)),
            entries(full + 1),
        ] {
            assert!(matches!(over.encode(), Err(MessageError::Encode(_))));
            // Sent anyway, it is refused on arrival.
            let bytes = postcard::to_stdvec(&over).unwrap();
            assert!(bytes.len() < MAX_WIRE_MESSAGE_SIZE);
            assert!(matches!(
                ListingsMessage::decode(&bytes),
                Err(MessageError::Decode(_))
            ));
        }
    }

    #[test]
    fn decoding_ignores_trailing_bytes() {
        // Postcard stops at the end of a whole message and leaves what
        // follows. It is part of the protocol (see the README), so it is pinned here.
        for message in one_of_each() {
            let bytes = message.encode().unwrap();
            for trailing in [vec![0x00], vec![0xff, 0x13, 0x37], bytes.clone()] {
                let mut longer = bytes.clone();
                longer.extend_from_slice(&trailing);
                assert_eq!(ListingsMessage::decode(&longer), Ok(message.clone()));
            }
        }
    }

    #[test]
    fn checks_changes_pages() {
        let request = changes_request(5);
        let changes = vec![
            entry_at(6, address(0x81, 1)),
            removed_at(9, address(0x90, 2)),
            entry_at(12, address(0xff, 3)),
        ];
        // More to come after 12, or nothing more.
        assert_eq!(
            check_changes_page(&request, &changes_response(20, 12, changes.clone())),
            Ok(ChangesPage::Follows(Some(12)))
        );
        assert_eq!(
            check_changes_page(&request, &changes_response(12, 12, changes)),
            Ok(ChangesPage::Follows(None))
        );
        // Nothing new since 5.
        assert_eq!(
            check_changes_page(&request, &changes_response(5, 5, Vec::new())),
            Ok(ChangesPage::Follows(None))
        );
        // Records read, none in the range: a page with nothing in it still
        // moves on.
        assert_eq!(
            check_changes_page(&request, &changes_response(20, 9, Vec::new())),
            Ok(ChangesPage::Follows(Some(9)))
        );
        // At most the limit asked for, and never more than MAX_LIST_LIMIT.
        let full = MAX_LIST_LIMIT as usize;
        let page: Vec<FeedChange> = (0..full)
            .map(|n| entry_at(6 + u64::try_from(n).unwrap(), nth_upper(n)))
            .collect();
        for limit in [MAX_LIST_LIMIT, u32::MAX] {
            let wide = ChangesRequest {
                limit,
                ..request.clone()
            };
            assert_eq!(
                check_changes_page(&wide, &changes_response(1_000, 261, page.clone())),
                Ok(ChangesPage::Follows(Some(261)))
            );
        }
    }

    #[test]
    fn refuses_bad_changes_pages() {
        let request = changes_request(5);
        let check = |response: &ChangesResponse| check_changes_page(&request, response);
        let a = address(0x81, 1);
        let b = address(0x90, 2);
        let good = changes_response(
            20,
            12,
            vec![
                entry_at(6, a),
                removed_at(9, b),
                entry_at(12, address(0xff, 3)),
            ],
        );
        assert!(check(&good).is_ok());

        // More than asked for, or than MAX_LIST_LIMIT.
        let eleven: Vec<FeedChange> = (0..11)
            .map(|n| entry_at(6 + u64::try_from(n).unwrap(), nth_upper(n)))
            .collect();
        assert_eq!(
            check(&changes_response(20, 16, eleven)),
            Err(FeedError::TooMany { count: 11, max: 10 })
        );
        let over: Vec<FeedChange> = (0..=MAX_LIST_LIMIT as usize)
            .map(|n| entry_at(6 + u64::try_from(n).unwrap(), nth_upper(n)))
            .collect();
        let wide = ChangesRequest {
            limit: u32::MAX,
            ..request.clone()
        };
        assert_eq!(
            check_changes_page(&wide, &changes_response(1_000, 262, over)),
            Err(FeedError::TooMany {
                count: 257,
                max: 256
            })
        );

        // next before after or beyond head; more that doesn't fit; more
        // without moving on.
        let mut bad = changes_response(20, 4, Vec::new());
        assert_eq!(check(&bad), Err(FeedError::BadNext));
        bad = good.clone();
        bad.next = 21;
        assert_eq!(check(&bad), Err(FeedError::BadNext));
        bad = good.clone();
        bad.more = false;
        assert_eq!(check(&bad), Err(FeedError::BadNext));
        bad = changes_response(12, 12, Vec::new());
        bad.more = true;
        assert_eq!(check(&bad), Err(FeedError::BadNext));
        let stuck = changes_response(20, 5, Vec::new());
        assert!(stuck.more);
        assert_eq!(check(&stuck), Err(FeedError::BadNext));

        // Records out of order, at or before after, beyond next, or twice.
        for changes in [
            vec![entry_at(9, a), entry_at(6, b)],
            vec![entry_at(5, a)],
            vec![entry_at(13, a)],
            vec![entry_at(6, a), entry_at(6, b)],
        ] {
            assert_eq!(
                check(&changes_response(20, 12, changes)),
                Err(FeedError::OutOfSequence)
            );
        }
        // An address outside the range, and one address twice.
        assert_eq!(
            check(&changes_response(
                20,
                12,
                vec![entry_at(6, address(0x7f, 1))]
            )),
            Err(FeedError::OutOfRange)
        );
        assert_eq!(
            check(&changes_response(
                20,
                12,
                vec![entry_at(6, a), removed_at(9, a)]
            )),
            Err(FeedError::RepeatedAddress)
        );
        // Epoch 0 is no node's.
        bad = good;
        bad.epoch = 0;
        assert_eq!(check(&bad), Err(FeedError::NoEpoch));
    }

    #[test]
    fn says_when_a_feed_must_be_read_afresh() {
        // Another epoch.
        assert_eq!(
            check_changes_page(&changes_request(5), &restart(78, 40)),
            Ok(ChangesPage::Restart {
                epoch: 78,
                head: 40
            })
        );
        // Asked with no epoch yet: whatever the node's is.
        let first = ChangesRequest {
            epoch: 0,
            after: 0,
            ..changes_request(0)
        };
        assert_eq!(
            check_changes_page(&first, &restart(77, 40)),
            Ok(ChangesPage::Restart {
                epoch: 77,
                head: 40
            })
        );
        assert_eq!(
            check_changes_page(&first, &restart(77, 0)),
            Ok(ChangesPage::Restart { epoch: 77, head: 0 })
        );
        // The same epoch, its head behind what the request has seen: the
        // feed went back.
        assert_eq!(
            check_changes_page(&changes_request(50), &restart(77, 40)),
            Ok(ChangesPage::Restart {
                epoch: 77,
                head: 40
            })
        );
        // Such an answer carries no changes and stops at the head.
        let mut bad = restart(78, 40);
        bad.changes = vec![entry_at(1, address(0x81, 1))];
        assert_eq!(
            check_changes_page(&changes_request(5), &bad),
            Err(FeedError::BadRestart)
        );
        bad = restart(78, 40);
        bad.next = 39;
        bad.more = true;
        assert_eq!(
            check_changes_page(&changes_request(5), &bad),
            Err(FeedError::BadRestart)
        );
        bad = restart(77, 40);
        bad.more = true;
        assert_eq!(
            check_changes_page(&changes_request(50), &bad),
            Err(FeedError::BadRestart)
        );
        assert_eq!(
            check_changes_page(&first, &restart(0, 40)),
            Err(FeedError::NoEpoch)
        );
    }

    #[test]
    fn checks_the_peers_against_the_view() {
        let peers: Vec<[u8; 32]> = (0..20).map(|n| [n; 32]).collect();
        let asked = ChangesRequest {
            want_peers: true,
            ..changes_request(5)
        };
        let mut response = ChangesResponse {
            view: view_hash(&peers),
            peers: peers.clone(),
            ..changes_response(5, 5, Vec::new())
        };
        assert_eq!(
            check_changes_page(&asked, &response),
            Ok(ChangesPage::Follows(None))
        );
        // In any order.
        response.peers.reverse();
        assert!(check_changes_page(&asked, &response).is_ok());
        // Not asked for.
        assert_eq!(
            check_changes_page(&changes_request(5), &response),
            Err(FeedError::UnaskedPeers)
        );
        // Not the ones the view hashes.
        response.peers.pop();
        assert_eq!(
            check_changes_page(&asked, &response),
            Err(FeedError::WrongView)
        );
        response.peers.clear();
        assert_eq!(
            check_changes_page(&asked, &response),
            Err(FeedError::WrongView)
        );
        // None, and the view of none.
        response.view = view_hash(&[]);
        assert!(check_changes_page(&asked, &response).is_ok());
        // Too many, even if the view matches them.
        let many: Vec<[u8; 32]> = (0..21).map(|n| [n; 32]).collect();
        response.view = view_hash(&many);
        response.peers = many;
        assert_eq!(
            check_changes_page(&asked, &response),
            Err(FeedError::TooManyPeers { count: 21, max: 20 })
        );
        // An answer from another feed is checked the same way.
        let restarted = ChangesResponse {
            peers: vec![[1; 32]],
            view: view_hash(&[[1; 32]]),
            ..restart(78, 40)
        };
        assert!(check_changes_page(&asked, &restarted).is_ok());
        assert_eq!(
            check_changes_page(&changes_request(5), &restarted),
            Err(FeedError::UnaskedPeers)
        );
    }

    #[test]
    fn checks_range_pages() {
        let entries: Vec<DigestEntry> = [address(0x80, 0), address(0x80, 1), address(0xc0, 0)]
            .into_iter()
            .map(feed_entry)
            .collect();
        let page = |entries: &[DigestEntry], more| RangeListResponse {
            entries: entries.to_vec(),
            more,
        };
        let from_start = range_request(None, 10);
        assert_eq!(
            check_range_page(&from_start, &page(&entries, true)),
            Ok(Some(address(0xc0, 0)))
        );
        assert_eq!(
            check_range_page(&from_start, &page(&entries, false)),
            Ok(None)
        );
        // An empty page can't move on, whatever the node says.
        assert_eq!(check_range_page(&from_start, &page(&[], true)), Ok(None));
        // From after an address.
        let after = range_request(Some(address(0x80, 0)), 2);
        assert_eq!(
            check_range_page(&after, &page(&entries[1..], true)),
            Ok(Some(address(0xc0, 0)))
        );
        // The range's last address ends it.
        let last = [feed_entry([0xff; 32])];
        assert_eq!(check_range_page(&from_start, &page(&last, true)), Ok(None));
        // Never more than MAX_LIST_LIMIT, whatever the limit.
        let full: Vec<DigestEntry> = (0..MAX_LIST_LIMIT as usize)
            .map(|n| feed_entry(nth_upper(n)))
            .collect();
        assert_eq!(
            check_range_page(&range_request(None, u32::MAX), &page(&full, true)),
            Ok(Some(nth_upper(255)))
        );
    }

    #[test]
    fn refuses_bad_range_pages() {
        let entries: Vec<DigestEntry> = [address(0x80, 0), address(0x80, 1), address(0xc0, 0)]
            .into_iter()
            .map(feed_entry)
            .collect();
        let check = |request: &RangeListRequest, entries: &[DigestEntry]| {
            check_range_page(
                request,
                &RangeListResponse {
                    entries: entries.to_vec(),
                    more: true,
                },
            )
        };
        assert_eq!(
            check(&range_request(None, 2), &entries),
            Err(FeedError::TooMany { count: 3, max: 2 })
        );
        let over: Vec<DigestEntry> = (0..=MAX_LIST_LIMIT as usize)
            .map(|n| feed_entry(nth_upper(n)))
            .collect();
        assert_eq!(
            check(&range_request(None, u32::MAX), &over),
            Err(FeedError::TooMany {
                count: 257,
                max: 256
            })
        );
        assert_eq!(
            check(&range_request(None, 10), &[feed_entry(address(0x7f, 0))]),
            Err(FeedError::OutOfRange)
        );
        let request = range_request(None, 10);
        let mut swapped = entries.clone();
        swapped.swap(0, 2);
        assert_eq!(check(&request, &swapped), Err(FeedError::OutOfOrder));
        assert_eq!(
            check(&request, &[entries[0], entries[0]]),
            Err(FeedError::OutOfOrder)
        );
        // At or before the address asked after.
        for at in [address(0x80, 1), address(0x80, 2)] {
            assert_eq!(
                check(&range_request(Some(at), 10), &entries[1..]),
                Err(FeedError::OutOfOrder)
            );
        }
    }

    #[test]
    fn checks_pushes() {
        let range = AddressRange::new([0x80; 32], 1);
        let push = ChangesResponse {
            more: false,
            ..changes_response(
                12,
                12,
                vec![
                    entry_at(11, address(0x81, 1)),
                    removed_at(12, address(0x90, 2)),
                ],
            )
        };
        assert_eq!(check_push(range, &push), Ok(()));
        // Any records up to the head, from the first on.
        let mut early = push.clone();
        early.changes[0] = entry_at(1, address(0x81, 1));
        assert_eq!(check_push(range, &early), Ok(()));

        let refused = |change: fn(&mut ChangesResponse)| {
            let mut bad = push.clone();
            change(&mut bad);
            check_push(range, &bad)
        };
        assert_eq!(
            refused(|bad| bad.peers = vec![[1; 32]]),
            Err(FeedError::UnaskedPeers)
        );
        assert_eq!(refused(|bad| bad.epoch = 0), Err(FeedError::NoEpoch));
        assert_eq!(refused(|bad| bad.more = true), Err(FeedError::BadNext));
        assert_eq!(refused(|bad| bad.next = 11), Err(FeedError::BadNext));
        assert_eq!(
            refused(|bad| bad.changes[0] = entry_at(0, address(0x81, 1))),
            Err(FeedError::OutOfSequence)
        );
        assert_eq!(
            refused(|bad| bad.changes[1] = removed_at(13, address(0x90, 2))),
            Err(FeedError::OutOfSequence)
        );
        assert_eq!(
            refused(|bad| bad.changes[0] = entry_at(11, address(0x01, 1))),
            Err(FeedError::OutOfRange)
        );
        assert_eq!(
            refused(|bad| bad.changes[1] = removed_at(12, address(0x81, 1))),
            Err(FeedError::RepeatedAddress)
        );
    }

    #[test]
    fn pushes_have_the_complement_of_the_watching_requests_id() {
        assert_eq!(push_request_id(0), u64::MAX);
        assert_eq!(push_request_id(7), 0xffff_ffff_ffff_fff8);
        for id in [0, 1, 7, 300, u64::MAX / 2, u64::MAX / 2 + 1, u64::MAX] {
            // Never the request's own id, and the request's from the push's.
            assert_ne!(push_request_id(id), id);
            assert_eq!(push_request_id(push_request_id(id)), id);
        }
        // On the wire: a push for a watch that request 7 set.
        let push = ListingsMessage {
            request_id: push_request_id(7),
            body: ListingsBody::ChangesResponse(changes_response(
                12,
                12,
                vec![removed_at(12, address(0x90, 2))],
            )),
        };
        let ListingsBody::ChangesResponse(response) = &push.body else {
            unreachable!()
        };
        assert_eq!(
            check_push(AddressRange::new([0x80; 32], 1), response),
            Ok(())
        );
        let bytes = push.encode().unwrap();
        let expected = crate::proof::decode_hex(concat!(
            "f8ffffffffffffffff01", // request id: the complement of 7
            "06",                   // ChangesResponse
        ))
        .unwrap();
        assert_eq!(&bytes[..expected.len()], expected.as_slice());
        assert_eq!(ListingsMessage::decode(&bytes), Ok(push));
    }
}
