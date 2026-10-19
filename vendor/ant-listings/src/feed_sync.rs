//! Following one node's change feed: a reader's mirror of what the node
//! serves in an address range.
//!
//! [`FeedSync`] keeps the mirror and says what to ask the node next. Each
//! round (a poll) it asks for the changes after the last record it has
//! ([`ChangesRequest`]), pages on while the node has more, and once it has
//! reached the node's head checks its count and set hash against the
//! node's. While they match, the mirror is exact, and once the node has
//! answered in the round its copies can count ([`FeedSync::in_sync`]). When
//! they don't, or the node's feed is new to the mirror (another epoch, or a
//! head behind the mirror's), it reads the range afresh
//! ([`RangeListRequest`]), over several rounds if need be, then follows the
//! feed again from the head the node gave when the reading began. A push
//! from a watch ([`ChangesRequest::watch`]) is taken between polls when it
//! brings the mirror exactly to the node's new head, and left to the next
//! request otherwise ([`FeedSync::push`]).
//!
//! A node can make up as many entries as it likes, so a fixed cap on what is
//! read from a node would cap the index too. As in
//! [`IndexWalk`](crate::IndexWalk), a node is read for as long as other nodes
//! back what it serves: its allowance is [`WALK_FREE_LISTINGS`] entries, and
//! [`WALK_PER_BACKED`] more for each entry in its mirror whose address at
//! least [`QUORUM_THRESHOLD`](crate::QUORUM_THRESHOLD) of the
//! [`NEAREST_NODES`](crate::NEAREST_NODES) nodes nearest it serve, counted
//! where the node is among the [`WALK_EARNING_RANKS`](crate::WALK_EARNING_RANKS)
//! nearest the address. The caller counts those across its mirrors, in sync
//! or not, and passes the count in ([`FeedSync::set_backed`]). In a round, a
//! node is asked for at most its allowance's worth of full pages, however few
//! records each holds, each push counting as a page too. Until the node has
//! answered in the round, pushes leave a page for its answer, and the round's
//! first request is sent whatever they have used, so each round asks the node
//! at least once. Its mirror never grows past its allowance: each request
//! after the round's first needs room in it for a full page of new addresses.
//! If the round's first request finds no room, the mirror starts again from
//! nothing: it is emptied when the answer comes, and the range is read
//! afresh. Only the node's answers can shrink its mirror, so they are
//! never held back for want of room: a mirror holding entries the node no
//! longer serves is put right as the node answers, even when nobody serves
//! them any more and they earn it nothing. A node holding real listings
//! earns as it goes; one serving entries nobody else serves is read for
//! eight pages a round, as a walk reads it, and its mirror stays within
//! [`WALK_FREE_LISTINGS`] entries.
//!
//! Nothing here does I/O. The caller starts each round with
//! [`FeedSync::begin_round`], sends each request [`FeedSync::next_request`]
//! gives, passes back the answer with [`FeedSync::answer`] or the lack of one
//! with [`FeedSync::no_answer`], recounts the addresses an answer changed
//! and passes the new count of backed entries to [`FeedSync::set_backed`],
//! and ends the round with [`FeedSync::stop`].

use crate::feed::{AddressRange, DigestEntry, FeedChange, SetHash};
use crate::message::{
    check_changes_page, check_push, check_range_page, ChangesPage, ChangesRequest, ChangesResponse,
    ListingsBody, RangeListRequest, RangeListResponse, MAX_LIST_LIMIT,
};
use crate::walk::{WALK_FREE_LISTINGS, WALK_PER_BACKED, WALK_RETRY_PAGES};
use ant_protocol::XorName;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;

/// The records a full page counts for, against a node's allowance, however
/// few it holds.
const PAGE: usize = MAX_LIST_LIMIT as usize;

/// Where a node's round stands, or how it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedOutcome {
    /// The node answered this round, and the mirror is at the head it
    /// reported this round, with the count and set hash it reported: its
    /// copies count.
    Synced,
    /// The node had been asked for all it had earned before the mirror got
    /// there: the rest waits for the next round.
    Budget,
    /// The caller stopped the round ([`FeedSync::stop`]) before the mirror
    /// got there.
    Deadline,
    /// The node stopped answering, or never answered.
    NoAnswer,
    /// The node sent an answer the checks refuse.
    BadPage,
}

/// What became of a push ([`FeedSync::push`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pushed {
    /// Taken: the mirror is at the push's head, with the count and set hash
    /// it gives. The addresses whose entries changed.
    Applied(Vec<XorName>),
    /// Not taken: the mirror lacks a record the push doesn't carry. The node
    /// is ahead of the mirror until a request catches up.
    Behind,
    /// Left alone: malformed, from another epoch, no further on than the
    /// mirror, sent while the range is read afresh, or beyond what the
    /// node's allowance leaves for pushes.
    Ignored,
}

/// A reader's mirror of what one node serves in an address range, and what to
/// ask the node next. See the module docs.
#[derive(Debug, Clone)]
pub struct FeedSync {
    range: AddressRange,
    /// The epoch the mirror follows; 0 before it follows one.
    epoch: u64,
    /// The number of the last record the mirror reflects.
    head: u64,
    phase: Phase,
    entries: BTreeMap<XorName, DigestEntry>,
    set_hash: SetHash,
    backed: usize,
    /// Pages answered this round, pushes included.
    pages: usize,
    /// Whether the node has answered a request this round.
    answered: bool,
    retries: usize,
    asked: Option<Asked>,
    /// Whether the request waiting for its answer starts the mirror again
    /// from nothing.
    afresh: bool,
    /// Where the node said its feed stood this round, furthest on.
    reported: Option<Report>,
    ended: Option<FeedOutcome>,
    problem: Option<String>,
    view: Option<[u8; 32]>,
    peers: Option<Vec<[u8; 32]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing is known of the node's feed yet.
    Start,
    /// The mirror follows the feed after its head.
    Following,
    /// Reading the range afresh after `cursor`; then the feed is followed
    /// after `head`, in `epoch`.
    Reading {
        epoch: u64,
        head: u64,
        cursor: Option<XorName>,
    },
}

#[derive(Debug, Clone)]
enum Asked {
    Changes(ChangesRequest),
    Range(RangeListRequest),
}

/// Where a node said its feed stood, with its count and set hash for the
/// range there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Report {
    epoch: u64,
    head: u64,
    count: u64,
    set_hash: SetHash,
}

impl FeedSync {
    /// An empty mirror of what a node serves in `range`. Its first request
    /// asks the node where its feed stands.
    #[must_use]
    pub fn new(range: AddressRange) -> Self {
        Self {
            range,
            epoch: 0,
            head: 0,
            phase: Phase::Start,
            entries: BTreeMap::new(),
            set_hash: SetHash::EMPTY,
            backed: 0,
            pages: 0,
            answered: false,
            retries: 0,
            asked: None,
            afresh: false,
            reported: None,
            ended: None,
            problem: None,
            view: None,
            peers: None,
        }
    }

    /// A mirror kept from before, such as by an earlier run: the entries it
    /// held of what the node served in `range`, at record `head` of `epoch`
    /// ([`epoch`](Self::epoch), [`head`](Self::head) and
    /// [`entries`](Self::entries) give them). Its first request asks for the
    /// changes after `head`. Entries outside `range` are left out. With
    /// epoch 0 it starts as [`new`](Self::new) does, keeping the entries
    /// until the range is read afresh. Give it its count of backed entries
    /// ([`set_backed`](Self::set_backed)) before its first request: a mirror
    /// without room for a full page within its allowance starts again from
    /// nothing.
    #[must_use]
    pub fn resume(
        range: AddressRange,
        epoch: u64,
        head: u64,
        entries: impl IntoIterator<Item = DigestEntry>,
    ) -> Self {
        let mut sync = Self::new(range);
        for entry in entries {
            if range.contains(&entry.address) {
                sync.put(entry);
            }
        }
        if epoch != 0 {
            sync.epoch = epoch;
            sync.head = head;
            sync.phase = Phase::Following;
        }
        sync
    }

    /// Start a round: forget the last round's answers, so the node must
    /// answer again for its copies to count, and give it a new allowance of
    /// pages.
    pub fn begin_round(&mut self) {
        self.pages = 0;
        self.answered = false;
        self.retries = 0;
        self.asked = None;
        self.afresh = false;
        self.reported = None;
        self.ended = None;
        self.problem = None;
    }

    /// Set how many entries in the mirror are backed: their address is
    /// served by at least [`QUORUM_THRESHOLD`](crate::QUORUM_THRESHOLD) of
    /// the [`NEAREST_NODES`](crate::NEAREST_NODES) nodes nearest it, and this
    /// node is among the [`WALK_EARNING_RANKS`](crate::WALK_EARNING_RANKS)
    /// nearest it. Count from what each mirror holds, whether or not it is in
    /// sync, so that a round in which nodes don't answer leaves their
    /// backing as it was. Keep it up to date as mirrors change, after each
    /// answer and push.
    pub fn set_backed(&mut self, backed: usize) {
        self.backed = backed;
    }

    /// The request to send the node next, if any: none while one waits for
    /// its answer, once the round has ended, or while the mirror is in sync.
    /// It is marked as waiting for its answer. `want_peers` and `watch` go
    /// into a [`ChangesRequest`] (see there), and are left out of a
    /// [`RangeListRequest`]. Send each request with a request id of its own.
    /// A watch's pushes come with
    /// [`push_request_id`](crate::push_request_id) of the id of the request
    /// that set it, and can arrive before that request's answer: pass them to
    /// [`push`](Self::push).
    ///
    /// The round's first request is sent even if the round's pushes have
    /// used the node's allowance, or the mirror has no room left for a full
    /// page within it. Without room, it starts the mirror again from
    /// nothing: the mirror is emptied when the answer comes, and the range
    /// is read afresh.
    pub fn next_request(&mut self, want_peers: bool, watch: bool) -> Option<ListingsBody> {
        if self.ended.is_some() || self.asked.is_some() || self.in_sync() {
            return None;
        }
        if !self.may_ask() {
            self.ended = Some(FeedOutcome::Budget);
            return None;
        }
        let afresh = !self.has_room();
        let (prefix, bits) = (self.range.prefix(), self.range.bits());
        let changes = |epoch, after| ChangesRequest {
            epoch,
            after,
            prefix,
            bits,
            limit: MAX_LIST_LIMIT,
            want_peers,
            watch,
        };
        let asked = match self.phase {
            Phase::Start => Asked::Changes(changes(0, 0)),
            Phase::Following => Asked::Changes(changes(self.epoch, self.head)),
            // Starting again from nothing, the range is read from its start.
            Phase::Reading { cursor, .. } => Asked::Range(RangeListRequest {
                prefix,
                bits,
                after: cursor.filter(|_| !afresh),
                limit: MAX_LIST_LIMIT,
            }),
        };
        let body = match &asked {
            Asked::Changes(request) => ListingsBody::ChangesRequest(request.clone()),
            Asked::Range(request) => ListingsBody::RangeListRequest(request.clone()),
        };
        self.asked = Some(asked);
        self.afresh = afresh;
        Some(body)
    }

    /// The node's answer to the request waiting for one. Returns the
    /// addresses whose entries in the mirror changed, for the caller to
    /// count again: if the request started the mirror again from nothing,
    /// every address it held that the answer doesn't keep. An answer the
    /// checks refuse, or one that doesn't answer the request, ends the round
    /// ([`FeedOutcome::BadPage`]); an [`Error`](ListingsBody::Error) counts
    /// as no answer. An answer when nothing is waiting, such as after
    /// [`stop`](Self::stop), is ignored.
    pub fn answer(&mut self, body: ListingsBody) -> Vec<XorName> {
        let Some(asked) = self.asked.take() else {
            return Vec::new();
        };
        let afresh = std::mem::take(&mut self.afresh);
        match (asked, body) {
            (Asked::Changes(request), ListingsBody::ChangesResponse(response)) => {
                self.take_changes(&request, response, afresh)
            }
            (Asked::Range(request), ListingsBody::RangeListResponse(response)) => {
                self.take_range(&request, response, afresh)
            }
            (_, ListingsBody::Error { .. }) => {
                self.missed();
                Vec::new()
            }
            _ => {
                self.refuse("the answer is not one to the request".into());
                Vec::new()
            }
        }
    }

    /// The node didn't answer the request waiting for one: it timed out. The
    /// node is asked again once a round, and once more for every
    /// [`WALK_RETRY_PAGES`] pages it has answered in the round; after that
    /// its round ends ([`FeedOutcome::NoAnswer`]).
    pub fn no_answer(&mut self) {
        if self.asked.take().is_some() {
            self.afresh = false;
            self.missed();
        }
    }

    /// A push from the node's watch on this range: a message from the node
    /// whose request id is [`push_request_id`](crate::push_request_id) of
    /// the id of a request that set a watch, whether it comes before or after
    /// that request's answer. Taken if it brings the mirror exactly to the
    /// push's head, within the node's allowance, of which a page is kept for
    /// the node's answer until it has answered this round: the push is then
    /// the node's report this round, and the mirror is in sync once the node
    /// has also answered a request this round. If it doesn't bring the mirror
    /// there, the node is ahead of the mirror, and
    /// [`next_request`](Self::next_request) asks it to catch up. Check that
    /// the push came from the node before passing it in.
    pub fn push(&mut self, push: &ChangesResponse) -> Pushed {
        let allowance = self.allowance();
        if self.phase != Phase::Following
            || push.epoch != self.epoch
            || push.head <= self.head
            || check_push(self.range, push).is_err()
            || PAGE.saturating_mul(self.pages + 1 + usize::from(!self.answered)) > allowance
        {
            return Pushed::Ignored;
        }
        let (count, set_hash) = self.with_changes(&push.changes);
        let fits = (count, set_hash) == (push.count, push.set_hash);
        if fits && count > u64::try_from(allowance).unwrap_or(u64::MAX) {
            return Pushed::Ignored;
        }
        self.pages += 1;
        self.view = Some(push.view);
        self.note(Report {
            epoch: push.epoch,
            head: push.head,
            count: push.count,
            set_hash: push.set_hash,
        });
        if !fits {
            return Pushed::Behind;
        }
        let touched = self.apply(&push.changes);
        self.head = push.head;
        Pushed::Applied(touched)
    }

    /// End the round, at the caller's deadline. A node that has used what it
    /// earned ends as [`FeedOutcome::Budget`], any other not in sync as
    /// [`FeedOutcome::Deadline`]. Answers that come in later are ignored;
    /// pushes are still taken.
    pub fn stop(&mut self) {
        self.asked = None;
        self.afresh = false;
        if self.ended.is_none() && !self.in_sync() {
            self.ended = Some(if self.may_ask() {
                FeedOutcome::Deadline
            } else {
                FeedOutcome::Budget
            });
        }
    }

    /// Follow another range, such as the node's new leaf. Entries outside it
    /// leave the mirror, and are returned for the caller to count again. A
    /// range within the old one carries on from the mirror's head; any other
    /// is read afresh first. The node's reports were for the old range, so
    /// the mirror is in sync again only once the node reports on the new one.
    pub fn rescope(&mut self, range: AddressRange) -> Vec<XorName> {
        let outside: Vec<XorName> = self
            .entries
            .keys()
            .filter(|address| !range.contains(address))
            .copied()
            .collect();
        for address in &outside {
            self.remove(address);
        }
        let within = self.range.covers(&range);
        self.range = range;
        self.asked = None;
        self.afresh = false;
        self.reported = None;
        self.phase = match self.phase {
            Phase::Start => Phase::Start,
            Phase::Following if within => Phase::Following,
            Phase::Following => Phase::Reading {
                epoch: self.epoch,
                head: self.head,
                cursor: None,
            },
            Phase::Reading { epoch, head, .. } => Phase::Reading {
                epoch,
                head,
                cursor: None,
            },
        };
        outside
    }

    /// Whether the node has answered a request this round, and the mirror is
    /// at the head the node reported this round, with the count and set hash
    /// it reported there: whether its copies count. A push alone doesn't
    /// make a round's mirror in sync, so each round asks the node at least
    /// once, which also renews its watch.
    #[must_use]
    pub fn in_sync(&self) -> bool {
        self.answered
            && self.phase == Phase::Following
            && self.reported.is_some_and(|report| {
                report.epoch == self.epoch && report.head == self.head && self.matches(&report)
            })
    }

    /// How the round stands: [`FeedOutcome::Synced`] while in sync,
    /// otherwise how it ended, or `None` while it goes on.
    #[must_use]
    pub fn outcome(&self) -> Option<FeedOutcome> {
        if self.in_sync() {
            Some(FeedOutcome::Synced)
        } else {
            self.ended
        }
    }

    /// Why the node's last answer was refused, for [`FeedOutcome::BadPage`].
    #[must_use]
    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Whether a request is waiting for its answer.
    #[must_use]
    pub fn waiting(&self) -> bool {
        self.asked.is_some()
    }

    /// Whether nothing waits for an answer and nothing more can be asked
    /// this round.
    #[must_use]
    pub fn idle(&self) -> bool {
        self.asked.is_none() && (self.ended.is_some() || self.in_sync() || !self.may_ask())
    }

    /// The pages the node answered this round, each push counting as one.
    #[must_use]
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// The range followed.
    #[must_use]
    pub fn range(&self) -> AddressRange {
        self.range
    }

    /// The epoch the mirror follows: 0 before it first follows one.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of the last record the mirror reflects.
    #[must_use]
    pub fn head(&self) -> u64 {
        self.head
    }

    /// How many entries the mirror holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry the mirror holds for `address`.
    #[must_use]
    pub fn get(&self, address: &XorName) -> Option<&DigestEntry> {
        self.entries.get(address)
    }

    /// The entries the mirror holds, in address order.
    pub fn entries(&self) -> impl Iterator<Item = &DigestEntry> {
        self.entries.values()
    }

    /// The set hash of the entries the mirror holds.
    #[must_use]
    pub fn set_hash(&self) -> SetHash {
        self.set_hash
    }

    /// The node's latest view hash, from its last answer or push.
    #[must_use]
    pub fn view(&self) -> Option<[u8; 32]> {
        self.view
    }

    /// The node's nearest peers, from its last answer that listed them.
    #[must_use]
    pub fn peers(&self) -> Option<&[[u8; 32]]> {
        self.peers.as_deref()
    }

    fn take_changes(
        &mut self,
        request: &ChangesRequest,
        response: ChangesResponse,
        afresh: bool,
    ) -> Vec<XorName> {
        let page = match check_changes_page(request, &response) {
            Ok(page) => page,
            Err(e) => {
                self.refuse(e.to_string());
                return Vec::new();
            }
        };
        self.pages += 1;
        self.answered = true;
        let ChangesResponse {
            epoch,
            head,
            next,
            count,
            set_hash,
            changes,
            view,
            peers,
            ..
        } = response;
        self.view = Some(view);
        if request.want_peers {
            self.peers = Some(peers);
        }
        self.note(Report {
            epoch,
            head,
            count,
            set_hash,
        });
        if afresh {
            // Start again from nothing: read the range afresh, then follow
            // the feed after where it stands now.
            self.phase = Phase::Reading {
                epoch,
                head,
                cursor: None,
            };
            return self.replace(None, self.range.last(), Vec::new());
        }
        match page {
            ChangesPage::Restart { epoch, head } => {
                self.phase = Phase::Reading {
                    epoch,
                    head,
                    cursor: None,
                };
                Vec::new()
            }
            ChangesPage::Follows(_) => {
                let touched = self.apply(&changes);
                self.head = self.head.max(next);
                self.read_afresh_if_wrong();
                touched
            }
        }
    }

    fn take_range(
        &mut self,
        request: &RangeListRequest,
        response: RangeListResponse,
        afresh: bool,
    ) -> Vec<XorName> {
        let Phase::Reading { epoch, head, .. } = self.phase else {
            return Vec::new();
        };
        let next = match check_range_page(request, &response) {
            Ok(next) => next,
            Err(e) => {
                self.refuse(e.to_string());
                return Vec::new();
            }
        };
        self.pages += 1;
        self.answered = true;
        // Starting again from nothing, the rest of the range goes too: the
        // request asked from its start.
        let through = match next {
            Some(next) if !afresh => next,
            _ => self.range.last(),
        };
        let touched = self.replace(request.after, through, response.entries);
        if next.is_some() {
            self.phase = Phase::Reading {
                epoch,
                head,
                cursor: next,
            };
        } else {
            // Read to the end: the records after `head` bring the mirror up
            // to date, whatever changed while the range was read.
            self.epoch = epoch;
            self.head = head;
            self.phase = Phase::Following;
        }
        touched
    }

    /// Keep `report` as where the node's feed stands, unless one kept this
    /// round is further on in the same epoch.
    fn note(&mut self, report: Report) {
        if self
            .reported
            .is_none_or(|kept| kept.epoch != report.epoch || kept.head <= report.head)
        {
            self.reported = Some(report);
        }
    }

    /// Once the mirror has reached the head the node reported, read the
    /// range afresh if it doesn't hold what the node reported there.
    fn read_afresh_if_wrong(&mut self) {
        if let Some(report) = self.reported {
            if self.phase == Phase::Following
                && report.epoch == self.epoch
                && report.head == self.head
                && !self.matches(&report)
            {
                self.phase = Phase::Reading {
                    epoch: self.epoch,
                    head: self.head,
                    cursor: None,
                };
            }
        }
    }

    fn matches(&self, report: &Report) -> bool {
        report.count == self.count() && report.set_hash == self.set_hash
    }

    fn count(&self) -> u64 {
        u64::try_from(self.entries.len()).unwrap_or(u64::MAX)
    }

    fn allowance(&self) -> usize {
        WALK_FREE_LISTINGS.saturating_add(WALK_PER_BACKED.saturating_mul(self.backed))
    }

    /// Whether the node may be asked another page this round: always until
    /// it has answered this round (see [`next_request`](Self::next_request)),
    /// and after that while it has earned another page and its mirror has
    /// room for a full page of new addresses.
    fn may_ask(&self) -> bool {
        !self.answered
            || (PAGE.saturating_mul(self.pages + 1) <= self.allowance() && self.has_room())
    }

    /// Whether the mirror has room within the allowance for a full page of
    /// new addresses.
    fn has_room(&self) -> bool {
        self.entries.len().saturating_add(PAGE) <= self.allowance()
    }

    fn missed(&mut self) {
        if self.retries < 1 + self.pages / WALK_RETRY_PAGES {
            self.retries += 1;
        } else {
            self.ended = Some(FeedOutcome::NoAnswer);
        }
    }

    fn refuse(&mut self, problem: String) {
        self.ended = Some(FeedOutcome::BadPage);
        self.problem = Some(problem);
    }

    /// Apply the records after the mirror's head, in order. Earlier ones are
    /// in it already: a push took the mirror past them.
    fn apply(&mut self, changes: &[FeedChange]) -> Vec<XorName> {
        let head = self.head;
        let mut touched = Vec::new();
        for change in changes.iter().filter(|change| change.seq() > head) {
            let changed = match change {
                FeedChange::Entry { entry, .. } => self.put(*entry),
                FeedChange::Removed { address, .. } => self.remove(address),
            };
            if changed {
                touched.push(change.address());
            }
        }
        touched
    }

    /// The count and set hash the mirror would have with `changes` applied,
    /// one per address.
    fn with_changes(&self, changes: &[FeedChange]) -> (u64, SetHash) {
        let mut count = self.entries.len();
        let mut set_hash = self.set_hash;
        for change in changes.iter().filter(|change| change.seq() > self.head) {
            if let Some(old) = self.entries.get(&change.address()) {
                count -= 1;
                set_hash.remove(old);
            }
            if let Some(entry) = change.entry() {
                count += 1;
                set_hash.insert(entry);
            }
        }
        (u64::try_from(count).unwrap_or(u64::MAX), set_hash)
    }

    /// Make the mirror hold `entries` and nothing else after `after` (or
    /// from the range's start) through `through`.
    fn replace(
        &mut self,
        after: Option<XorName>,
        through: XorName,
        entries: Vec<DigestEntry>,
    ) -> Vec<XorName> {
        let fresh: HashSet<XorName> = entries.iter().map(|entry| entry.address).collect();
        let stale: Vec<XorName> = if after.is_some_and(|after| after >= through) {
            Vec::new()
        } else {
            let from = after.map_or(Bound::Included(self.range.first()), Bound::Excluded);
            self.entries
                .range((from, Bound::Included(through)))
                .map(|(address, _)| *address)
                .filter(|address| !fresh.contains(address))
                .collect()
        };
        let mut touched = Vec::new();
        for address in stale {
            if self.remove(&address) {
                touched.push(address);
            }
        }
        for entry in entries {
            let address = entry.address;
            if self.put(entry) {
                touched.push(address);
            }
        }
        touched
    }

    /// Hold `entry` for its address. Returns whether the mirror changed.
    fn put(&mut self, entry: DigestEntry) -> bool {
        match self.entries.insert(entry.address, entry) {
            Some(old) if old == entry => false,
            Some(old) => {
                self.set_hash.remove(&old);
                self.set_hash.insert(&entry);
                true
            }
            None => {
                self.set_hash.insert(&entry);
                true
            }
        }
    }

    /// Hold nothing for `address`. Returns whether the mirror changed.
    fn remove(&mut self, address: &XorName) -> bool {
        match self.entries.remove(address) {
            Some(old) => {
                self.set_hash.remove(&old);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Metadata;
    use crate::feed::{leaves, view_hash};
    use crate::flags::{Flags, PaymentField, ShownFields};
    use crate::listing::{Listing, ListingPayment};
    use crate::message::VIEW_PEERS;
    use crate::payment::QUORUM_THRESHOLD;
    use crate::walk::{nearest_by_distance, NEAREST_NODES, WALK_EARNING_RANKS};
    use std::collections::HashMap;

    const NOW: u64 = 1_800_000_000;
    const HOUR: u64 = NOW - NOW % 3_600;

    /// 32 bytes from `seed`, spread by splitmix64.
    fn id(seed: u64) -> [u8; 32] {
        let mut state = seed;
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
        }
        bytes
    }

    /// The entry for a listing in the index showing every field but the
    /// quote, paid in `block`.
    fn real(address: XorName, block: u64) -> DigestEntry {
        DigestEntry::new(&Listing {
            address,
            flags: Flags {
                shown: ShownFields::ALL.without(PaymentField::Quote),
                in_index: true,
                withheld: false,
            },
            metadata: Metadata::default(),
            size: Some(1_000),
            payment: ListingPayment {
                tx_hash: Some(id(block)),
                block_number: Some(block),
                block_timestamp: Some(NOW - 1_000_000 + block * 2),
                log_index: Some(0),
                quote: None,
            },
            first_seen: None,
        })
    }

    /// A made-up entry, dated this hour.
    fn fake(address: XorName) -> DigestEntry {
        DigestEntry {
            address,
            time: HOUR,
            block_number: 0,
            log_index: 0,
            first_seen: Some(HOUR),
            digest: [0xfa; 32],
        }
    }

    /// An address starting with `prefix` and ending with `n`.
    fn made_up(prefix: &[u8], n: u64) -> XorName {
        let mut address = [0u8; 32];
        address[..prefix.len()].copy_from_slice(prefix);
        address[24..].copy_from_slice(&n.to_be_bytes());
        address
    }

    #[derive(Clone)]
    enum Behaviour {
        /// Answers as the protocol says.
        Honest,
        /// Answers every request with `per_page` made-up entries at
        /// addresses starting with `prefix`, always saying there are more.
        Flood { prefix: Vec<u8>, per_page: usize },
        /// Never answers.
        Silent,
        /// Answers `pages` requests, then never again.
        Stalls { pages: usize },
        /// Answers as the protocol says, but with a set hash that never
        /// matches what it serves.
        WrongHash,
    }

    /// A test node: what it serves in the index, and its change feed.
    #[derive(Clone)]
    struct Node {
        epoch: u64,
        head: u64,
        rows: BTreeMap<u64, FeedChange>,
        seq_of: HashMap<XorName, u64>,
        served: BTreeMap<XorName, DigestEntry>,
        peers: Vec<[u8; 32]>,
        behaviour: Behaviour,
        /// Requests it was sent.
        asked: usize,
        /// How many records this test node reads for one request.
        reads: usize,
        states: HashMap<(AddressRange, u64, u64), (u64, SetHash)>,
    }

    impl Node {
        fn new(epoch: u64, peers: Vec<[u8; 32]>) -> Self {
            Self {
                epoch,
                head: 0,
                rows: BTreeMap::new(),
                seq_of: HashMap::new(),
                served: BTreeMap::new(),
                peers,
                behaviour: Behaviour::Honest,
                asked: 0,
                reads: 4_096,
                states: HashMap::new(),
            }
        }

        /// Serve `entry`: a new record if it changes what the node serves.
        fn serve(&mut self, entry: DigestEntry) {
            if self.served.insert(entry.address, entry) != Some(entry) {
                self.record(entry.address, FeedChange::Entry { seq: 0, entry });
            }
        }

        /// Serve nothing at `address` any more.
        fn unserve(&mut self, address: XorName) {
            if self.served.remove(&address).is_some() {
                self.record(address, FeedChange::Removed { seq: 0, address });
            }
        }

        /// Number `change` next, in place of the address's last record.
        fn record(&mut self, address: XorName, change: FeedChange) {
            self.head += 1;
            let seq = self.head;
            if let Some(old) = self.seq_of.insert(address, seq) {
                self.rows.remove(&old);
            }
            let change = match change {
                FeedChange::Entry { entry, .. } => FeedChange::Entry { seq, entry },
                FeedChange::Removed { address, .. } => FeedChange::Removed { seq, address },
            };
            self.rows.insert(seq, change);
        }

        /// Lose everything served, and number the feed afresh in a new
        /// epoch: a wiped store.
        fn wipe(&mut self, epoch: u64) {
            self.served.clear();
            self.renumber(epoch);
        }

        /// Number everything served afresh, in a new epoch.
        fn renumber(&mut self, epoch: u64) {
            self.epoch = epoch;
            self.head = 0;
            self.rows.clear();
            self.seq_of.clear();
            let served: Vec<DigestEntry> = self.served.values().copied().collect();
            for entry in served {
                self.record(entry.address, FeedChange::Entry { seq: 0, entry });
            }
        }

        /// The count and set hash of what the node serves in `range`.
        fn state(&mut self, range: AddressRange) -> (u64, SetHash) {
            let key = (range, self.epoch, self.head);
            if let Some(state) = self.states.get(&key) {
                return *state;
            }
            let entries: Vec<&DigestEntry> = self
                .served
                .range(range.first()..=range.last())
                .map(|(_, entry)| entry)
                .collect();
            let state = (u64::try_from(entries.len()).unwrap(), SetHash::of(entries));
            self.states.insert(key, state);
            state
        }

        fn answer(&mut self, body: &ListingsBody) -> Option<ListingsBody> {
            self.asked += 1;
            match self.behaviour.clone() {
                Behaviour::Silent => None,
                Behaviour::Stalls { pages } if self.asked > pages => None,
                Behaviour::Flood { prefix, per_page } => Some(self.flood(body, &prefix, per_page)),
                _ => Some(match body {
                    ListingsBody::ChangesRequest(request) => {
                        ListingsBody::ChangesResponse(self.changes(request))
                    }
                    ListingsBody::RangeListRequest(request) => {
                        ListingsBody::RangeListResponse(self.range_list(request))
                    }
                    _ => ListingsBody::Error {
                        message: "not a request".into(),
                    },
                }),
            }
        }

        fn changes(&mut self, request: &ChangesRequest) -> ChangesResponse {
            let range = request.range();
            let (count, mut set_hash) = self.state(range);
            if matches!(self.behaviour, Behaviour::WrongHash) {
                set_hash += SetHash::from_bytes([1; 32]);
            }
            let mut response = ChangesResponse {
                epoch: self.epoch,
                head: self.head,
                next: self.head,
                count,
                set_hash,
                changes: Vec::new(),
                more: false,
                view: view_hash(&self.peers),
                peers: if request.want_peers {
                    self.peers.clone()
                } else {
                    Vec::new()
                },
            };
            if request.epoch != self.epoch || request.after > self.head {
                return response;
            }
            let limit = usize::try_from(request.limit.min(MAX_LIST_LIMIT)).unwrap();
            let mut next = request.after;
            for (&seq, change) in self
                .rows
                .range((Bound::Excluded(request.after), Bound::Unbounded))
                .take(self.reads)
            {
                if response.changes.len() == limit {
                    break;
                }
                next = seq;
                if range.contains(&change.address()) {
                    response.changes.push(*change);
                }
            }
            response.next = next;
            response.more = next < self.head;
            response
        }

        fn range_list(&self, request: &RangeListRequest) -> RangeListResponse {
            let range = request.range();
            let from = request
                .after
                .map_or(Bound::Included(range.first()), Bound::Excluded);
            let limit = usize::try_from(request.limit.min(MAX_LIST_LIMIT)).unwrap();
            let mut entries: Vec<DigestEntry> = self
                .served
                .range((from, Bound::Included(range.last())))
                .map(|(_, entry)| *entry)
                .take(limit + 1)
                .collect();
            let more = entries.len() > limit;
            entries.truncate(limit);
            RangeListResponse { entries, more }
        }

        /// A push of the records in `range` after `after`.
        fn push(&mut self, range: AddressRange, after: u64) -> ChangesResponse {
            let (count, set_hash) = self.state(range);
            ChangesResponse {
                epoch: self.epoch,
                head: self.head,
                next: self.head,
                count,
                set_hash,
                changes: self
                    .rows
                    .range((Bound::Excluded(after), Bound::Unbounded))
                    .map(|(_, change)| *change)
                    .filter(|change| range.contains(&change.address()))
                    .collect(),
                more: false,
                view: view_hash(&self.peers),
                peers: Vec::new(),
            }
        }

        /// Made-up entries, `per_page` at a time, each answer saying there
        /// are more: new records without end in the node's own epoch, and
        /// entries without end when the range is read.
        fn flood(&self, body: &ListingsBody, prefix: &[u8], per_page: usize) -> ListingsBody {
            let per_page = u64::try_from(per_page).unwrap();
            let endless = u64::MAX / 2;
            match body {
                ListingsBody::ChangesRequest(request) if request.epoch == self.epoch => {
                    ListingsBody::ChangesResponse(ChangesResponse {
                        epoch: self.epoch,
                        head: endless,
                        next: request.after + per_page,
                        count: endless,
                        set_hash: SetHash::EMPTY,
                        changes: (request.after + 1..=request.after + per_page)
                            .map(|seq| FeedChange::Entry {
                                seq,
                                entry: fake(made_up(prefix, seq)),
                            })
                            .collect(),
                        more: true,
                        view: view_hash(&[]),
                        peers: Vec::new(),
                    })
                }
                ListingsBody::ChangesRequest(_) => ListingsBody::ChangesResponse(ChangesResponse {
                    epoch: self.epoch,
                    head: endless,
                    next: endless,
                    count: endless,
                    set_hash: SetHash::EMPTY,
                    changes: Vec::new(),
                    more: false,
                    view: view_hash(&[]),
                    peers: Vec::new(),
                }),
                ListingsBody::RangeListRequest(request) => {
                    let start = request
                        .after
                        .filter(|after| after.starts_with(prefix))
                        .map_or(0, |after| {
                            u64::from_be_bytes(after[24..].try_into().unwrap()) + 1
                        });
                    ListingsBody::RangeListResponse(RangeListResponse {
                        entries: (start..start + per_page)
                            .map(|n| fake(made_up(prefix, n)))
                            .collect(),
                        more: true,
                    })
                }
                _ => ListingsBody::Error {
                    message: "not a request".into(),
                },
            }
        }
    }

    struct Net {
        ids: Vec<[u8; 32]>,
        nodes: Vec<Node>,
    }

    impl Net {
        fn new(count: usize, seed: u64) -> Self {
            let ids: Vec<[u8; 32]> = (0..count).map(|n| id(seed * 1_000 + n as u64)).collect();
            let nodes = (0..count)
                .map(|n| {
                    let peers = nearest_by_distance(&ids[n], &ids, VIEW_PEERS + 1)
                        .into_iter()
                        .filter(|&peer| peer != n)
                        .take(VIEW_PEERS)
                        .map(|peer| ids[peer])
                        .collect();
                    let epoch =
                        u64::from_be_bytes(id(seed * 7 + n as u64)[..8].try_into().unwrap());
                    Node::new(epoch | 1, peers)
                })
                .collect();
            Self { ids, nodes }
        }

        /// Store listings `from` to `from + count`, each on its 7 nearest
        /// nodes and, for every third, also on the nodes ranked 8 to 12.
        /// Their addresses.
        fn store(&mut self, from: u64, count: u64) -> Vec<XorName> {
            let mut addresses = Vec::new();
            for n in from..from + count {
                let address = id(1_000_000 + n);
                let entry = real(address, n + 1);
                let holders = if n % 3 == 0 { 12 } else { NEAREST_NODES };
                for node in nearest_by_distance(&address, &self.ids, holders) {
                    self.nodes[node].serve(entry);
                }
                addresses.push(address);
            }
            addresses
        }

        /// What `node` serves in `range`.
        fn served(&self, node: usize, range: AddressRange) -> Vec<DigestEntry> {
            self.nodes[node]
                .served
                .range(range.first()..=range.last())
                .map(|(_, entry)| *entry)
                .collect()
        }
    }

    /// A reader: a mirror of each node's leaf, and the counts of backed
    /// entries it keeps as the mirrors change.
    struct Reader {
        ids: Vec<[u8; 32]>,
        syncs: Vec<FeedSync>,
        /// The nodes whose mirrors hold each address.
        holders: HashMap<XorName, Vec<usize>>,
        /// Whether a quorum of each address's nearest nodes hold it.
        backed: HashMap<XorName, bool>,
        /// Each node's backed entries, where it earns from them.
        counts: Vec<usize>,
        /// The nodes nearest each address, as far as earning goes.
        ranked: HashMap<XorName, Vec<usize>>,
    }

    impl Reader {
        fn new(ids: &[[u8; 32]]) -> Self {
            let mut syncs = vec![FeedSync::new(AddressRange::ALL); ids.len()];
            for leaf in leaves(ids) {
                for &node in &leaf.nodes {
                    syncs[node] = FeedSync::new(leaf.range);
                }
            }
            Self {
                ids: ids.to_vec(),
                syncs,
                holders: HashMap::new(),
                backed: HashMap::new(),
                counts: vec![0; ids.len()],
                ranked: HashMap::new(),
            }
        }

        /// A round: every node polled, then asked on until nothing is left to
        /// ask, each step's answers in an order shuffled by `seed`.
        fn round(&mut self, net: &mut Net, seed: u64) {
            for sync in &mut self.syncs {
                sync.begin_round();
            }
            let mut step = 0;
            loop {
                let mut asked: Vec<(usize, ListingsBody)> = self
                    .syncs
                    .iter_mut()
                    .enumerate()
                    .filter_map(|(node, sync)| Some((node, sync.next_request(false, false)?)))
                    .collect();
                if asked.is_empty() {
                    break;
                }
                asked.sort_by_key(|(node, _)| id(seed * 1_000_003 + step * 1_009 + *node as u64));
                for (node, body) in asked {
                    match net.nodes[node].answer(&body) {
                        Some(answer) => {
                            let touched = self.syncs[node].answer(answer);
                            self.recount(node, &touched);
                        }
                        None => self.syncs[node].no_answer(),
                    }
                }
                step += 1;
            }
            for sync in &mut self.syncs {
                sync.stop();
            }
        }

        /// Count again the addresses `touched` in `node`'s mirror, and give
        /// every mirror its count of backed entries.
        fn recount(&mut self, node: usize, touched: &[XorName]) {
            for address in touched {
                self.recount_address(node, *address);
            }
            for (sync, &count) in self.syncs.iter_mut().zip(&self.counts) {
                sync.set_backed(count);
            }
        }

        fn recount_address(&mut self, node: usize, address: XorName) {
            let ids = &self.ids;
            let ranked = self
                .ranked
                .entry(address)
                .or_insert_with(|| nearest_by_distance(&address, ids, WALK_EARNING_RANKS));
            let holders = self.holders.entry(address).or_default();
            let was_backed = self.backed.get(&address).copied().unwrap_or(false);
            let holds = self.syncs[node].get(&address).is_some();
            if holds != holders.contains(&node) {
                if holds {
                    holders.push(node);
                } else {
                    holders.retain(|&holder| holder != node);
                }
                if was_backed && ranked.contains(&node) {
                    if holds {
                        self.counts[node] += 1;
                    } else {
                        self.counts[node] -= 1;
                    }
                }
            }
            let nearest = &ranked[..NEAREST_NODES.min(ranked.len())];
            let support = holders
                .iter()
                .filter(|holder| nearest.contains(holder))
                .count();
            let backed = support >= QUORUM_THRESHOLD;
            if backed != was_backed {
                self.backed.insert(address, backed);
                for &holder in holders.iter().filter(|holder| ranked.contains(holder)) {
                    if backed {
                        self.counts[holder] += 1;
                    } else {
                        self.counts[holder] -= 1;
                    }
                }
            }
        }

        /// Whether a quorum of the nodes nearest `address` hold it in their
        /// mirrors.
        fn is_backed(&self, address: &XorName) -> bool {
            self.backed.get(address).copied().unwrap_or(false)
        }

        /// How many of the nodes nearest `address` serve it from a mirror in
        /// sync: the copies that count.
        fn support(&self, address: &XorName) -> usize {
            nearest_by_distance(address, &self.ids, NEAREST_NODES)
                .into_iter()
                .filter(|&node| {
                    self.syncs[node].in_sync() && self.syncs[node].get(address).is_some()
                })
                .count()
        }

        /// Check the counts kept as mirrors changed against a count from
        /// scratch.
        fn check_counts(&self) {
            for (node, sync) in self.syncs.iter().enumerate() {
                let backed = sync
                    .entries()
                    .filter(|entry| {
                        let ranked =
                            nearest_by_distance(&entry.address, &self.ids, WALK_EARNING_RANKS);
                        let support = ranked[..NEAREST_NODES]
                            .iter()
                            .filter(|&&near| self.syncs[near].get(&entry.address).is_some())
                            .count();
                        support >= QUORUM_THRESHOLD && ranked.contains(&node)
                    })
                    .count();
                assert_eq!(self.counts[node], backed, "node {node}");
            }
        }

        /// The mirror of `node` holds exactly what it serves in its range.
        fn mirrors(&self, net: &Net, node: usize) -> bool {
            let sync = &self.syncs[node];
            sync.entries().copied().collect::<Vec<_>>() == net.served(node, sync.range())
        }
    }

    #[test]
    fn mirrors_sync_from_nothing_and_stay_in_sync() {
        let mut net = Net::new(24, 1);
        let addresses = net.store(0, 3_000);
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 1);
        for (node, sync) in reader.syncs.iter().enumerate() {
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced), "node {node}");
            assert_eq!(sync.epoch(), net.nodes[node].epoch);
            assert_eq!(sync.head(), net.nodes[node].head);
            assert!(reader.mirrors(&net, node), "node {node}");
            assert_eq!(sync.set_hash(), SetHash::of(sync.entries()));
        }
        for address in &addresses {
            assert_eq!(reader.support(address), NEAREST_NODES);
        }
        reader.check_counts();
        // Nothing new: one poll each.
        reader.round(&mut net, 2);
        for sync in &reader.syncs {
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced));
            assert_eq!(sync.pages(), 1);
        }
    }

    #[test]
    fn honest_feeds_have_no_ceiling() {
        // Over 5,000 entries a node in its leaf, far past the free eight
        // pages, so every mirror has to earn its way.
        let mut net = Net::new(24, 2);
        let addresses = net.store(0, 20_000);
        for seed in 0..2 {
            let mut reader = Reader::new(&net.ids);
            for (node, sync) in reader.syncs.iter().enumerate() {
                assert!(net.served(node, sync.range()).len() > 2 * WALK_FREE_LISTINGS);
            }
            reader.round(&mut net, seed);
            for (node, sync) in reader.syncs.iter().enumerate() {
                assert_eq!(sync.outcome(), Some(FeedOutcome::Synced), "node {node}");
                assert!(reader.mirrors(&net, node));
            }
            for address in &addresses {
                assert_eq!(reader.support(address), NEAREST_NODES);
            }
        }
    }

    #[test]
    fn a_node_serving_endless_fakes_stops_after_eight_pages_and_nothing_fake_is_backed() {
        let mut net = Net::new(24, 1);
        let addresses = net.store(0, 5_000);
        let prefix = net.ids[0][..8].to_vec();
        net.nodes[0].behaviour = Behaviour::Flood {
            prefix: prefix.clone(),
            per_page: PAGE,
        };
        let mut reader = Reader::new(&net.ids);

        // Its poll and seven pages of its range: eight pages.
        reader.round(&mut net, 7);
        assert_eq!(reader.syncs[0].pages(), 8);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Budget));
        assert_eq!(reader.syncs[0].len(), 7 * PAGE);
        // The next round fills its free allowance. After that, each round
        // finds no room in its mirror, so the mirror starts again from
        // nothing and the range is read afresh: eight pages a round, as a
        // walk reads it, and never more in the mirror.
        reader.round(&mut net, 8);
        assert_eq!(reader.syncs[0].pages(), 1);
        assert_eq!(reader.syncs[0].len(), WALK_FREE_LISTINGS);
        for seed in 9..12 {
            let asked = net.nodes[0].asked;
            reader.round(&mut net, seed);
            assert_eq!(net.nodes[0].asked, asked + 8);
            assert_eq!(reader.syncs[0].pages(), 8);
            assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Budget));
            assert_eq!(reader.syncs[0].len(), WALK_FREE_LISTINGS);
        }
        reader.check_counts();
        for entry in reader.syncs[0].entries() {
            assert!(entry.address.starts_with(&prefix));
            assert_eq!(
                reader.holders[&entry.address],
                [0],
                "served by its maker only"
            );
            assert!(!reader.is_backed(&entry.address));
        }
        assert_eq!(reader.counts[0], 0);
        for sync in &reader.syncs[1..] {
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced));
        }
        for address in &addresses {
            assert!(reader.support(address) >= NEAREST_NODES - 1);
        }
    }

    #[test]
    fn a_feed_making_endless_records_stops_within_its_allowance() {
        // In sync first, then a node makes up records without end in its
        // own epoch.
        let mut net = Net::new(24, 6);
        net.store(0, 3_000);
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 1);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        let held = reader.syncs[0].len();
        net.nodes[0].behaviour = Behaviour::Flood {
            prefix: net.ids[0][..8].to_vec(),
            per_page: PAGE,
        };
        let mut total = 0;
        for seed in 2..6 {
            reader.round(&mut net, seed);
            let sync = &reader.syncs[0];
            let allowance = WALK_FREE_LISTINGS + WALK_PER_BACKED * reader.counts[0];
            assert_eq!(sync.outcome(), Some(FeedOutcome::Budget));
            assert!(PAGE * sync.pages() <= allowance);
            assert!(sync.len() <= allowance);
            total += sync.pages();
        }
        // Its real entries earn it a few pages until its mirror is full,
        // which then starts again from nothing; its made-up ones never earn
        // anything, and stop at its allowance.
        assert!(reader.counts[0] <= held);
        assert!(reader.syncs[0].len() <= WALK_FREE_LISTINGS + WALK_PER_BACKED * held);
        assert!(total > 0);
        for sync in &reader.syncs[1..] {
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced));
        }
    }

    #[test]
    fn relaying_real_listings_earns_a_bounded_allowance() {
        // Node 0 relays the real listings near it, half of them altered,
        // and that alone earns its way to the end: backing goes by address.
        let mut net = Net::new(24, 3);
        net.store(0, 10_000);
        let relayed: Vec<DigestEntry> = net.nodes[0].served.values().copied().collect();
        for entry in relayed.iter().step_by(2) {
            let mut altered = *entry;
            altered.digest[0] ^= 1;
            net.nodes[0].serve(altered);
        }
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 5);
        let relay = &reader.syncs[0];
        assert_eq!(relay.outcome(), Some(FeedOutcome::Synced));
        assert!(relay.len() > WALK_FREE_LISTINGS);
        assert!(PAGE * relay.pages() <= WALK_FREE_LISTINGS + WALK_PER_BACKED * reader.counts[0]);

        // Mixing 20,000 made-up entries in among them buys two for each
        // backed entry, and no more: the mirror never reaches the end.
        let mut net = Net::new(24, 3);
        net.store(0, 10_000);
        let prefix = net.ids[0][..8].to_vec();
        for n in 0..20_000 {
            net.nodes[0].serve(fake(made_up(&prefix, n)));
        }
        let mut reader = Reader::new(&net.ids);
        for seed in 0..4 {
            reader.round(&mut net, seed);
            let mixer = &reader.syncs[0];
            let allowance = WALK_FREE_LISTINGS + WALK_PER_BACKED * reader.counts[0];
            assert_eq!(mixer.outcome(), Some(FeedOutcome::Budget));
            assert!(PAGE * mixer.pages() <= allowance);
            assert!(mixer.len() <= allowance);
        }
        let fakes = reader.syncs[0]
            .entries()
            .filter(|entry| entry.address.starts_with(&prefix))
            .count();
        assert!(fakes > 0);
        assert!(fakes <= WALK_FREE_LISTINGS + reader.counts[0]);
        for entry in reader.syncs[0].entries() {
            if entry.address.starts_with(&prefix) {
                assert_eq!(reader.holders[&entry.address], [0]);
            }
        }
    }

    #[test]
    fn three_colluders_never_back_their_fakes() {
        // Three nodes whose ids share a long prefix, so they are among the
        // nearest to the addresses they make up.
        let mut net = Net::new(24, 4);
        let prefix = vec![0x5a; 12];
        for node in 0..3 {
            net.ids[node][..12].copy_from_slice(&prefix);
        }
        let addresses = net.store(0, 3_000);
        for node in 0..3 {
            net.nodes[node].behaviour = Behaviour::Flood {
                prefix: prefix.clone(),
                per_page: PAGE,
            };
        }
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 9);
        for sync in &reader.syncs[..3] {
            assert_eq!(sync.pages(), 8);
            assert_eq!(sync.outcome(), Some(FeedOutcome::Budget));
        }
        let fakes: Vec<&XorName> = reader
            .holders
            .keys()
            .filter(|address| address.starts_with(&prefix))
            .collect();
        assert!(!fakes.is_empty());
        for address in fakes {
            assert!(reader.holders[address].len() <= 3);
            assert!(!reader.is_backed(address));
        }
        for address in &addresses {
            assert!(reader.support(address) >= QUORUM_THRESHOLD);
        }
    }

    #[test]
    fn a_short_page_saying_there_are_more_costs_a_full_one() {
        let mut net = Net::new(24, 5);
        net.store(0, 1_000);
        net.nodes[0].behaviour = Behaviour::Flood {
            prefix: net.ids[0][..8].to_vec(),
            per_page: 1,
        };
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 1);
        assert_eq!(reader.syncs[0].pages(), 8);
        assert_eq!(reader.syncs[0].len(), 7);
        assert_eq!(net.nodes[0].asked, 8);
    }

    #[test]
    fn nodes_that_stop_answering_are_asked_again_then_left_until_the_next_round() {
        let mut net = Net::new(24, 8);
        net.store(0, 20_000);
        net.nodes[1].behaviour = Behaviour::Silent;
        net.nodes[2].behaviour = Behaviour::Stalls { pages: 10 };
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 4);

        let silent = &reader.syncs[1];
        assert_eq!(silent.outcome(), Some(FeedOutcome::NoAnswer));
        assert_eq!(silent.pages(), 0);
        assert!(silent.is_empty());
        assert_eq!(net.nodes[1].asked, 2, "asked once, then once more");

        let stalled = &reader.syncs[2];
        assert_eq!(stalled.outcome(), Some(FeedOutcome::NoAnswer));
        assert_eq!(stalled.pages(), 10);
        assert_eq!(net.nodes[2].asked, 12);
        // Its poll, then nine pages of its range.
        assert_eq!(stalled.len(), 9 * PAGE);

        // Answering again, it carries on from where it stopped, then catches
        // up with its feed.
        net.nodes[2].behaviour = Behaviour::Honest;
        let held = net.served(2, reader.syncs[2].range()).len();
        reader.round(&mut net, 5);
        assert_eq!(reader.syncs[2].outcome(), Some(FeedOutcome::Synced));
        assert!(reader.mirrors(&net, 2));
        assert_eq!(reader.syncs[2].pages(), held.div_ceil(PAGE) - 9 + 1);
    }

    #[test]
    fn mirrors_follow_new_listings_removals_and_changed_copies() {
        let mut net = Net::new(24, 9);
        let addresses = net.store(0, 2_000);
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 1);
        let added = net.store(2_000, 100);
        for address in &addresses[..50] {
            for node in &mut net.nodes {
                node.unserve(*address);
            }
        }
        let changed: Vec<DigestEntry> = net.nodes[5].served.values().take(20).copied().collect();
        for mut entry in changed {
            entry.digest[0] ^= 1;
            net.nodes[5].serve(entry);
        }
        reader.round(&mut net, 2);
        for (node, sync) in reader.syncs.iter().enumerate() {
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced), "node {node}");
            assert_eq!(sync.pages(), 1);
            assert!(reader.mirrors(&net, node), "node {node}");
        }
        for address in &addresses[..50] {
            assert_eq!(reader.support(address), 0);
        }
        for address in &added {
            assert_eq!(reader.support(address), NEAREST_NODES);
        }
        reader.check_counts();
    }

    #[test]
    fn short_reads_page_on_to_the_head() {
        let mut net = Net::new(24, 10);
        net.store(0, 500);
        for node in &mut net.nodes {
            node.reads = 200;
        }
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 1);
        let heads: Vec<u64> = reader.syncs.iter().map(FeedSync::head).collect();
        // Hundreds of new records a node, some outside its leaf: pages
        // short of the limit that still say there is more.
        net.store(500, 3_000);
        reader.round(&mut net, 2);
        for (node, sync) in reader.syncs.iter().enumerate() {
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced), "node {node}");
            assert!(reader.mirrors(&net, node));
            let records = usize::try_from(net.nodes[node].head - heads[node]).unwrap();
            assert!(records > 2 * 200, "{records}");
            assert_eq!(sync.pages(), records.div_ceil(200));
        }
    }

    #[test]
    fn a_new_epoch_is_read_afresh_and_so_is_a_feed_that_went_back() {
        let mut net = Net::new(24, 11);
        net.store(0, 2_000);
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 1);

        // Node 3 numbers its records afresh, in a new epoch.
        let epoch = net.nodes[3].epoch;
        net.nodes[3].renumber(epoch ^ 0xffff);
        net.store(2_000, 100);
        let earlier = net.nodes[5].clone();
        reader.round(&mut net, 2);
        for (node, sync) in reader.syncs.iter().enumerate() {
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced), "node {node}");
            assert!(reader.mirrors(&net, node));
        }
        assert_eq!(reader.syncs[3].epoch(), epoch ^ 0xffff);
        assert!(reader.syncs[3].pages() > 1);

        // Node 5 goes back to an earlier copy of its feed: the same epoch,
        // its head behind the mirror's.
        net.store(2_100, 100);
        reader.round(&mut net, 3);
        assert!(reader.syncs[5].head() > earlier.head);
        net.nodes[5] = earlier;
        reader.round(&mut net, 4);
        assert_eq!(reader.syncs[5].outcome(), Some(FeedOutcome::Synced));
        assert_eq!(reader.syncs[5].head(), net.nodes[5].head);
        assert!(reader.mirrors(&net, 5));
        reader.check_counts();
    }

    #[test]
    fn a_node_whose_set_hash_never_matches_never_counts() {
        let mut net = Net::new(24, 12);
        net.store(0, 3_000);
        net.nodes[4].behaviour = Behaviour::WrongHash;
        let mut reader = Reader::new(&net.ids);
        for seed in 0..3 {
            reader.round(&mut net, seed);
            let liar = &reader.syncs[4];
            assert_eq!(liar.outcome(), Some(FeedOutcome::Budget));
            assert!(!liar.in_sync());
            assert!(PAGE * liar.pages() <= WALK_FREE_LISTINGS + WALK_PER_BACKED * reader.counts[4]);
            for (node, sync) in reader.syncs.iter().enumerate() {
                if node != 4 {
                    assert_eq!(sync.outcome(), Some(FeedOutcome::Synced));
                }
            }
        }
        // What it serves is mirrored all the same; its copies just don't
        // count.
        assert!(reader.mirrors(&net, 4));
    }

    #[test]
    fn a_mirror_left_behind_is_put_right_the_next_round_its_node_answers() {
        // Node 0 misses the round in which most listings go, or the round in
        // which every node is read afresh after every store was wiped. Its
        // mirror then holds thousands of entries nobody else serves, far
        // more than it has earned, and only the node's answers can shrink
        // it.
        for wiped in [false, true] {
            let mut net = Net::new(24, 16);
            let addresses = net.store(0, 20_000);
            let mut reader = Reader::new(&net.ids);
            reader.round(&mut net, 1);
            assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
            let held = reader.syncs[0].len();
            assert!(held > 2 * WALK_FREE_LISTINGS, "{held} entries");

            net.nodes[0].behaviour = Behaviour::Silent;
            let kept = if wiped {
                for node in &mut net.nodes {
                    let epoch = node.epoch;
                    node.wipe(epoch ^ 0xffff);
                }
                net.store(20_000, 3_000)
            } else {
                for address in &addresses[..16_000] {
                    for node in &mut net.nodes {
                        node.unserve(*address);
                    }
                }
                addresses[16_000..].to_vec()
            };
            reader.round(&mut net, 2);
            assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::NoAnswer));
            assert_eq!(reader.syncs[0].len(), held);
            let allowance = WALK_FREE_LISTINGS + WALK_PER_BACKED * reader.counts[0];
            assert!(
                held + PAGE > allowance,
                "{held} entries, {allowance} allowed"
            );

            // Answering again, its mirror starts again from nothing with its
            // poll's answer, and its range is read afresh in the same round.
            net.nodes[0].behaviour = Behaviour::Honest;
            reader.round(&mut net, 3);
            let sync = &reader.syncs[0];
            assert_eq!(sync.outcome(), Some(FeedOutcome::Synced), "wiped: {wiped}");
            assert!(reader.mirrors(&net, 0));
            let serves = net.served(0, sync.range()).len();
            assert_eq!(sync.pages(), 1 + serves.div_ceil(PAGE).max(1));
            for (node, sync) in reader.syncs.iter().enumerate() {
                assert_eq!(sync.outcome(), Some(FeedOutcome::Synced), "node {node}");
            }
            for address in &kept {
                assert_eq!(reader.support(address), NEAREST_NODES);
            }
            reader.check_counts();
        }
    }

    /// A network in sync, and an address in node 0's leaf it doesn't serve.
    fn synced() -> (Net, Reader, XorName) {
        let mut net = Net::new(24, 13);
        net.store(0, 1_000);
        let mut reader = Reader::new(&net.ids);
        reader.round(&mut net, 1);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        let address = made_up(&net.ids[0][..8], 1);
        assert!(reader.syncs[0].range().contains(&address));
        (net, reader, address)
    }

    #[test]
    fn pushes_take_the_mirror_to_the_new_head_between_polls() {
        let (mut net, mut reader, address) = synced();
        let range = reader.syncs[0].range();
        let entry = real(address, 9_999);
        net.nodes[0].serve(entry);
        let push = net.nodes[0].push(range, reader.syncs[0].head());
        assert_eq!(reader.syncs[0].push(&push), Pushed::Applied(vec![address]));
        assert!(reader.syncs[0].in_sync());
        assert_eq!(reader.syncs[0].head(), net.nodes[0].head);
        assert_eq!(reader.syncs[0].get(&address), Some(&entry));
        // Nothing new the second time.
        assert_eq!(reader.syncs[0].push(&push), Pushed::Ignored);
        reader.round(&mut net, 2);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        assert_eq!(reader.syncs[0].pages(), 1);
        // A removal, pushed.
        net.nodes[0].unserve(address);
        let push = net.nodes[0].push(range, reader.syncs[0].head());
        assert_eq!(reader.syncs[0].push(&push), Pushed::Applied(vec![address]));
        assert!(reader.syncs[0].in_sync());
        assert!(reader.mirrors(&net, 0));
    }

    #[test]
    fn a_push_missing_a_record_waits_for_the_next_request() {
        let (mut net, mut reader, address) = synced();
        let range = reader.syncs[0].range();
        let head = reader.syncs[0].head();
        let other = made_up(&net.ids[0][..8], 2);
        net.nodes[0].serve(real(address, 9_998));
        net.nodes[0].serve(real(other, 9_999));
        // Only the second record arrives.
        let push = net.nodes[0].push(range, head + 1);
        assert_eq!(push.changes.len(), 1);
        assert_eq!(reader.syncs[0].push(&push), Pushed::Behind);
        assert!(!reader.syncs[0].in_sync());
        assert_eq!(reader.syncs[0].head(), head);
        // The node is ahead, so the mirror asks to catch up.
        let Some(ListingsBody::ChangesRequest(request)) =
            reader.syncs[0].next_request(false, false)
        else {
            panic!("a changes request");
        };
        assert_eq!(request.after, head);
        let answer = net.nodes[0]
            .answer(&ListingsBody::ChangesRequest(request))
            .unwrap();
        reader.syncs[0].answer(answer);
        assert!(reader.syncs[0].in_sync());
        assert!(reader.mirrors(&net, 0));
    }

    #[test]
    fn pushes_that_do_not_fit_are_ignored() {
        let (mut net, mut reader, address) = synced();
        let range = reader.syncs[0].range();
        let head = reader.syncs[0].head();
        net.nodes[0].serve(real(address, 9_999));
        let push = net.nodes[0].push(range, head);
        let ignored = |reader: &mut Reader, change: fn(&mut ChangesResponse)| {
            let mut bad = push.clone();
            change(&mut bad);
            reader.syncs[0].push(&bad)
        };
        assert_eq!(ignored(&mut reader, |bad| bad.epoch ^= 1), Pushed::Ignored);
        assert_eq!(
            ignored(&mut reader, |bad| bad.peers = vec![[1; 32]]),
            Pushed::Ignored
        );
        assert_eq!(
            ignored(&mut reader, |bad| bad.changes[0] = FeedChange::Removed {
                seq: bad.head,
                address: [0; 32].map(|_| 0xff) // the far end of the space
            }),
            Pushed::Ignored
        );
        let mut old = push.clone();
        old.head = head;
        old.next = head;
        old.changes.clear();
        assert_eq!(reader.syncs[0].push(&old), Pushed::Ignored);
        // While the range is read afresh.
        let mut reading = reader.syncs[0].clone();
        reading.rescope(AddressRange::ALL);
        assert_eq!(reading.push(&push), Pushed::Ignored);
        assert!(reader.syncs[0].in_sync());
        assert_eq!(reader.syncs[0].push(&push), Pushed::Applied(vec![address]));
    }

    #[test]
    fn a_late_answer_does_not_take_the_mirror_back() {
        let (mut net, mut reader, _) = synced();
        let range = reader.syncs[0].range();
        let head = reader.syncs[0].head();
        let entry = *reader.syncs[0].entries().next().unwrap();
        reader.syncs[0].begin_round();
        let request = reader.syncs[0].next_request(false, false).unwrap();
        // The node changes the entry; its answer is made; then it changes
        // the entry again and pushes that, which arrives first.
        let mut first = entry;
        first.digest[0] ^= 1;
        net.nodes[0].serve(first);
        let answer = net.nodes[0].answer(&request).unwrap();
        let mut second = entry;
        second.digest[0] ^= 2;
        net.nodes[0].serve(second);
        let push = net.nodes[0].push(range, head + 1);
        assert_eq!(
            reader.syncs[0].push(&push),
            Pushed::Applied(vec![entry.address])
        );
        assert_eq!(reader.syncs[0].head(), head + 2);
        // The answer's record is older than the mirror: left out.
        assert!(reader.syncs[0].answer(answer).is_empty());
        assert_eq!(reader.syncs[0].get(&entry.address), Some(&second));
        assert_eq!(reader.syncs[0].head(), head + 2);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        assert!(reader.mirrors(&net, 0));
    }

    #[test]
    fn a_push_that_overtakes_its_answer_does_no_harm() {
        // Pushes are told from answers by request id, so a push that comes
        // first is passed to push and the answer to answer, whether or not
        // the request asked for peers.
        for want_peers in [false, true] {
            let (mut net, mut reader, address) = synced();
            let range = reader.syncs[0].range();
            let other = made_up(&net.ids[0][..8], 2);
            // A change the poll's answer carries, then one pushed after it.
            net.nodes[0].serve(real(other, 9_998));
            reader.syncs[0].begin_round();
            let request = reader.syncs[0].next_request(want_peers, true).unwrap();
            let answer = net.nodes[0].answer(&request).unwrap();
            let head = net.nodes[0].head;
            net.nodes[0].serve(real(address, 9_999));
            let push = net.nodes[0].push(range, head);
            // The push arrives first: it lacks the answer's record.
            assert_eq!(reader.syncs[0].push(&push), Pushed::Behind);
            assert_eq!(reader.syncs[0].answer(answer), vec![other]);
            assert!(!reader.syncs[0].in_sync());
            // One more request catches up with the push.
            let request = reader.syncs[0].next_request(want_peers, true).unwrap();
            let answer = net.nodes[0].answer(&request).unwrap();
            assert_eq!(reader.syncs[0].answer(answer), vec![address]);
            assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
            assert_eq!(reader.syncs[0].pages(), 3);
            assert!(reader.mirrors(&net, 0));
        }
    }

    #[test]
    fn a_push_before_the_rounds_poll_does_not_stand_in_for_it() {
        let (mut net, mut reader, address) = synced();
        let range = reader.syncs[0].range();
        reader.syncs[0].begin_round();
        // A new listing, pushed before the round's poll is sent.
        net.nodes[0].serve(real(address, 9_999));
        let push = net.nodes[0].push(range, reader.syncs[0].head());
        assert_eq!(reader.syncs[0].push(&push), Pushed::Applied(vec![address]));
        assert_eq!(reader.syncs[0].head(), net.nodes[0].head);
        // The mirror is at the node's head, but the node hasn't answered
        // this round: its copies don't count yet, and the poll, which renews
        // the watch, is still sent.
        assert!(!reader.syncs[0].in_sync());
        assert_eq!(reader.syncs[0].outcome(), None);
        let Some(ListingsBody::ChangesRequest(request)) = reader.syncs[0].next_request(false, true)
        else {
            panic!("a changes request");
        };
        assert!(request.watch);
        assert_eq!(request.after, net.nodes[0].head);
        let answer = net.nodes[0]
            .answer(&ListingsBody::ChangesRequest(request))
            .unwrap();
        assert!(reader.syncs[0].answer(answer).is_empty());
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        assert_eq!(reader.syncs[0].pages(), 2);
        assert!(reader.mirrors(&net, 0));
    }

    #[test]
    fn pushes_before_the_rounds_poll_leave_a_page_for_it() {
        // A burst of new records, each pushed before the round's poll is
        // sent, as when the poll waits behind other nodes' polls. Then,
        // the second time, the node's backing falls before its poll is
        // sent, as when other mirrors drop entries it holds.
        for falls in [false, true] {
            let (mut net, mut reader, _) = synced();
            let range = reader.syncs[0].range();
            let prefix = net.ids[0][..8].to_vec();
            let allowance = WALK_FREE_LISTINGS + WALK_PER_BACKED * reader.counts[0];
            reader.syncs[0].begin_round();
            let mut taken = 0;
            for n in 0..1_000 {
                let head = reader.syncs[0].head();
                net.nodes[0].serve(fake(made_up(&prefix, n + 10)));
                match reader.syncs[0].push(&net.nodes[0].push(range, head)) {
                    Pushed::Applied(touched) => {
                        taken += 1;
                        reader.recount(0, &touched);
                    }
                    Pushed::Ignored => break,
                    Pushed::Behind => panic!("each push carries its record"),
                }
            }
            if falls {
                reader.syncs[0].set_backed(0);
            }
            // The poll goes out all the same, with its watch, and its
            // answer brings the mirror in sync.
            let Some(ListingsBody::ChangesRequest(request)) =
                reader.syncs[0].next_request(false, true)
            else {
                panic!("a changes request, falls: {falls}");
            };
            assert!(request.watch);
            let answer = net.nodes[0]
                .answer(&ListingsBody::ChangesRequest(request))
                .unwrap();
            let touched = reader.syncs[0].answer(answer);
            reader.recount(0, &touched);
            assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
            assert!(reader.mirrors(&net, 0));
            // The pushes stopped a page short of the node's allowance, and
            // the poll's answer took that page.
            assert_eq!(taken, allowance / PAGE - 1);
            assert_eq!(reader.syncs[0].pages(), allowance / PAGE);
        }
    }

    #[test]
    fn pushes_count_against_the_allowance() {
        let (mut net, mut reader, _) = synced();
        let range = reader.syncs[0].range();
        let prefix = net.ids[0][..8].to_vec();
        let backed = reader.counts[0];
        let allowance = WALK_FREE_LISTINGS + WALK_PER_BACKED * backed;
        // Made-up records pushed without end, each push true to the node's
        // own count and set hash: taken only while the node has pages left.
        let mut taken = 0;
        for n in 0..1_000 {
            let head = reader.syncs[0].head();
            net.nodes[0].serve(fake(made_up(&prefix, n + 10)));
            match reader.syncs[0].push(&net.nodes[0].push(range, head)) {
                Pushed::Applied(touched) => {
                    taken += 1;
                    reader.recount(0, &touched);
                }
                Pushed::Ignored => break,
                Pushed::Behind => panic!("each push carries its record"),
            }
        }
        assert!(taken > 0);
        assert!(PAGE * reader.syncs[0].pages() <= allowance);
        assert!(reader.syncs[0].len() <= allowance);
        // A new round gives more pages, until the mirror is full.
        for seed in 2..30 {
            reader.round(&mut net, seed);
            loop {
                let head = reader.syncs[0].head();
                let n = 10_000 + net.nodes[0].head;
                net.nodes[0].serve(fake(made_up(&prefix, n)));
                match reader.syncs[0].push(&net.nodes[0].push(range, head)) {
                    Pushed::Applied(touched) => reader.recount(0, &touched),
                    _ => break,
                }
            }
            assert!(
                reader.syncs[0].len() <= WALK_FREE_LISTINGS + WALK_PER_BACKED * reader.counts[0]
            );
        }
    }

    #[test]
    fn rescoping_keeps_what_is_still_in_range() {
        let (mut net, mut reader, _) = synced();
        let leaf = reader.syncs[0].range();
        let (lower, upper) = leaf.halves().unwrap();
        let half = if lower.contains(&net.ids[0]) {
            lower
        } else {
            upper
        };
        let outside = reader.syncs[0].rescope(half);
        assert!(!outside.is_empty());
        assert!(outside.iter().all(|address| !half.contains(address)));
        assert!(reader.syncs[0]
            .entries()
            .all(|entry| half.contains(&entry.address)));
        reader.recount(0, &outside);
        assert!(!reader.syncs[0].in_sync());
        // Within the old range: one poll.
        reader.round(&mut net, 2);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        assert_eq!(reader.syncs[0].pages(), 1);
        assert!(reader.mirrors(&net, 0));
        // Wider again: read afresh.
        assert!(reader.syncs[0].rescope(leaf).is_empty());
        reader.round(&mut net, 3);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        assert!(reader.syncs[0].pages() > 1);
        assert!(reader.mirrors(&net, 0));
    }

    #[test]
    fn a_kept_mirror_carries_on_from_its_head() {
        let (mut net, mut reader, _) = synced();
        let kept = &reader.syncs[0];
        let (range, epoch, head) = (kept.range(), kept.epoch(), kept.head());
        let mut entries: Vec<DigestEntry> = kept.entries().copied().collect();
        // One from elsewhere, which a mirror of this range leaves out.
        entries.push(fake([0xff; 32].map(|byte| byte ^ net.ids[0][0])));
        reader.syncs[0] = FeedSync::resume(range, epoch, head, entries.clone());
        assert_eq!(reader.syncs[0].len(), entries.len() - 1);
        net.store(1_000, 200);
        reader.round(&mut net, 2);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        assert_eq!(reader.syncs[0].pages(), 1);
        assert!(reader.mirrors(&net, 0));
        // Kept without an epoch, it reads the range afresh.
        reader.syncs[0] = FeedSync::resume(range, 0, head, entries);
        reader.round(&mut net, 3);
        assert_eq!(reader.syncs[0].outcome(), Some(FeedOutcome::Synced));
        assert!(reader.syncs[0].pages() > 1);
        assert!(reader.mirrors(&net, 0));
    }

    #[test]
    fn answers_that_are_not_pages_end_the_round_and_errors_count_as_none() {
        let mut sync = FeedSync::new(AddressRange::ALL);
        sync.begin_round();
        let Some(ListingsBody::ChangesRequest(request)) = sync.next_request(true, true) else {
            panic!("a changes request");
        };
        assert_eq!(
            (request.epoch, request.after, request.limit),
            (0, 0, MAX_LIST_LIMIT)
        );
        assert!(request.want_peers && request.watch);
        assert!(sync.waiting());
        assert_eq!(sync.next_request(false, false), None);
        // An error is no answer: asked again.
        assert!(sync
            .answer(ListingsBody::Error {
                message: "busy".into()
            })
            .is_empty());
        assert!(!sync.waiting());
        assert_eq!(sync.outcome(), None);
        assert!(sync.next_request(false, false).is_some());
        // An answer to another request ends the round.
        sync.answer(ListingsBody::ListResponse {
            listings: Vec::new(),
            more: false,
        });
        assert_eq!(sync.outcome(), Some(FeedOutcome::BadPage));
        assert!(sync.problem().is_some());
        assert_eq!(sync.next_request(false, false), None);
        assert!(sync.idle());
        // So does one the checks refuse.
        sync.begin_round();
        assert!(sync.next_request(false, false).is_some());
        sync.answer(ListingsBody::ChangesResponse(ChangesResponse {
            epoch: 0,
            head: 0,
            next: 0,
            count: 0,
            set_hash: SetHash::EMPTY,
            changes: Vec::new(),
            more: false,
            view: view_hash(&[]),
            peers: Vec::new(),
        }));
        assert_eq!(sync.outcome(), Some(FeedOutcome::BadPage));
        assert_eq!(sync.problem(), Some("the node gives epoch 0"));
        // Nothing waiting: ignored.
        assert!(sync
            .answer(ListingsBody::RangeListResponse(RangeListResponse {
                entries: Vec::new(),
                more: false
            }))
            .is_empty());
        // Twice without an answer, and the round is over.
        sync.begin_round();
        assert!(sync.next_request(false, false).is_some());
        sync.no_answer();
        assert!(sync.next_request(false, false).is_some());
        sync.no_answer();
        assert_eq!(sync.outcome(), Some(FeedOutcome::NoAnswer));
    }

    #[test]
    fn a_stopped_round_ignores_late_answers_and_the_next_carries_on() {
        let mut net = Net::new(24, 14);
        net.store(0, 20_000);
        let range = leaves(&net.ids)
            .into_iter()
            .find(|leaf| leaf.nodes.contains(&0))
            .unwrap()
            .range;
        let mut sync = FeedSync::new(range);
        sync.begin_round();
        for _ in 0..3 {
            let request = sync.next_request(false, false).unwrap();
            sync.answer(net.nodes[0].answer(&request).unwrap());
        }
        let late = sync.next_request(false, false).unwrap();
        sync.stop();
        assert_eq!(sync.outcome(), Some(FeedOutcome::Deadline));
        let held = sync.len();
        assert_eq!(held, 2 * PAGE);
        assert!(sync.answer(net.nodes[0].answer(&late).unwrap()).is_empty());
        assert_eq!(sync.len(), held);
        // The next round asks after the last address read.
        sync.begin_round();
        let Some(ListingsBody::RangeListRequest(request)) = sync.next_request(false, false) else {
            panic!("a range request");
        };
        assert_eq!(
            request.after,
            sync.entries().last().map(|entry| entry.address)
        );
    }

    #[test]
    fn the_nodes_view_and_peers_come_with_its_answers() {
        let mut net = Net::new(24, 15);
        net.store(0, 200);
        let mut sync = FeedSync::new(AddressRange::ALL);
        assert_eq!((sync.view(), sync.peers()), (None, None));
        sync.begin_round();
        let request = sync.next_request(true, false).unwrap();
        sync.answer(net.nodes[0].answer(&request).unwrap());
        assert_eq!(sync.view(), Some(view_hash(&net.nodes[0].peers)));
        assert_eq!(sync.peers(), Some(net.nodes[0].peers.as_slice()));
        assert_eq!(sync.peers().unwrap().len(), VIEW_PEERS);
        // Read to the end; range pages carry no view.
        while let Some(request) = sync.next_request(false, false) {
            sync.answer(net.nodes[0].answer(&request).unwrap());
        }
        assert_eq!(sync.outcome(), Some(FeedOutcome::Synced));
        // The node's neighbourhood changes: the next poll gives the new view
        // and keeps the last list until it is asked for again.
        net.nodes[0].peers.pop();
        sync.begin_round();
        let request = sync.next_request(false, false).unwrap();
        sync.answer(net.nodes[0].answer(&request).unwrap());
        assert_eq!(sync.view(), Some(view_hash(&net.nodes[0].peers)));
        assert_eq!(sync.peers().unwrap().len(), VIEW_PEERS);
        sync.begin_round();
        let request = sync.next_request(true, false).unwrap();
        sync.answer(net.nodes[0].answer(&request).unwrap());
        assert_eq!(sync.peers(), Some(net.nodes[0].peers.as_slice()));
    }
}
