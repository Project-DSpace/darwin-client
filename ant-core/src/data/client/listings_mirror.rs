//! A reader's mirror of what one node serves in an address range, following
//! the node's change feed, with the mirror's entries kept outside it: in the
//! listings producer's store ([`Feeds`](super::listings_feeds::Feeds)), so
//! that what the producer holds in memory doesn't grow with the index.
//!
//! [`MirrorSync`] is [`ant_listings::FeedSync`], the reader's state machine
//! of `ant-listings`, step for step: the same requests, the same checks of
//! every answer and push (by `ant-listings` itself: [`check_changes_page`],
//! [`check_range_page`], [`check_push`]), the same allowances and outcomes.
//! The one difference is where the mirror's entries are: `FeedSync` holds
//! them in memory, and a `MirrorSync` reads and writes them through the
//! [`Entries`] each call is given, keeping only how many there are and their
//! set hash. Each entry it puts or removes is reported to
//! [`Entries::touched`], in the order `FeedSync` returns them, for the
//! caller to count again.
//!
//! A test drives a `MirrorSync` and a `FeedSync` with the same answers, from
//! nodes that answer as the protocol says and from nodes that flood, stall,
//! lie about their totals, restart their feeds or wander out of range, and
//! checks after every step that they ask the same, end their rounds the same,
//! report the same addresses and hold the same entries.

use std::collections::HashSet;
use std::ops::Bound;

use ant_listings::{
    check_changes_page, check_push, check_range_page, AddressRange, ChangesPage, ChangesRequest,
    ChangesResponse, DigestEntry, FeedChange, FeedOutcome, ListingsBody, Pushed, RangeListRequest,
    RangeListResponse, SetHash, MAX_LIST_LIMIT, WALK_FREE_LISTINGS, WALK_PER_BACKED,
    WALK_RETRY_PAGES,
};
use ant_protocol::XorName;

/// The records a full page counts for, against a node's allowance, however
/// few it holds.
const PAGE: usize = MAX_LIST_LIMIT as usize;

/// How many of a mirror's addresses are read at a time when it is scanned
/// ([`Entries::scan`]): a page's worth.
const SCAN: usize = PAGE;

/// Where a mirror's entries are kept, for one node: read and written by a
/// [`MirrorSync`] in each of its calls.
pub(crate) trait Entries {
    /// The entry held for `address`.
    fn get(&self, address: &XorName) -> Option<DigestEntry>;

    /// Hold `entry` for its address, in place of any held.
    fn insert(&mut self, entry: DigestEntry);

    /// Hold nothing for `address`.
    fn delete(&mut self, address: &XorName);

    /// Up to `limit` of the addresses held from `from` through `through`, in
    /// address order.
    fn scan(&self, from: Bound<XorName>, through: XorName, limit: usize) -> Vec<XorName>;

    /// The entry held for `address` changed: it was put, replaced or
    /// removed.
    fn touched(&mut self, address: XorName);
}

/// Where a node's round stands. As `FeedSync`'s.
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

/// A reader's mirror of what one node serves in an address range, and what
/// to ask the node next, with its entries kept in an [`Entries`]. See the
/// module docs, and [`ant_listings::FeedSync`] for what each call does.
#[derive(Debug, Clone)]
pub(crate) struct MirrorSync {
    range: AddressRange,
    /// The epoch the mirror follows; 0 before it follows one.
    epoch: u64,
    /// The number of the last record the mirror reflects.
    head: u64,
    phase: Phase,
    /// How many entries the mirror holds.
    count: u64,
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

impl MirrorSync {
    /// An empty mirror of what a node serves in `range`: its [`Entries`]
    /// must hold none. As [`FeedSync::new`](ant_listings::FeedSync::new).
    #[must_use]
    pub(crate) fn new(range: AddressRange) -> Self {
        Self {
            range,
            epoch: 0,
            head: 0,
            phase: Phase::Start,
            count: 0,
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

    /// A mirror kept from before, whose [`Entries`] hold `count` entries,
    /// all in `range`, with `set_hash`, at record `head` of `epoch`. As
    /// [`FeedSync::resume`](ant_listings::FeedSync::resume) with those
    /// entries: with epoch 0 it starts as [`new`](Self::new) does, keeping
    /// the entries until the range is read afresh.
    #[must_use]
    pub(crate) fn resume(
        range: AddressRange,
        epoch: u64,
        head: u64,
        count: u64,
        set_hash: SetHash,
    ) -> Self {
        let mut sync = Self::new(range);
        sync.count = count;
        sync.set_hash = set_hash;
        if epoch != 0 {
            sync.epoch = epoch;
            sync.head = head;
            sync.phase = Phase::Following;
        }
        sync
    }

    /// Start a round. As `FeedSync`'s.
    pub(crate) fn begin_round(&mut self) {
        self.pages = 0;
        self.answered = false;
        self.retries = 0;
        self.asked = None;
        self.afresh = false;
        self.reported = None;
        self.ended = None;
        self.problem = None;
    }

    /// Set how many entries in the mirror are backed. As `FeedSync`'s.
    pub(crate) fn set_backed(&mut self, backed: usize) {
        self.backed = backed;
    }

    /// The request to send the node next, if any. As `FeedSync`'s.
    pub(crate) fn next_request(&mut self, want_peers: bool, watch: bool) -> Option<ListingsBody> {
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

    /// The node's answer to the request waiting for one, applied to
    /// `entries`. As `FeedSync`'s, but each address whose entry changed goes
    /// to [`Entries::touched`] instead of being returned.
    pub(crate) fn answer(&mut self, body: ListingsBody, entries: &mut impl Entries) {
        let Some(asked) = self.asked.take() else {
            return;
        };
        let afresh = std::mem::take(&mut self.afresh);
        match (asked, body) {
            (Asked::Changes(request), ListingsBody::ChangesResponse(response)) => {
                self.take_changes(&request, response, afresh, entries);
            }
            (Asked::Range(request), ListingsBody::RangeListResponse(response)) => {
                self.take_range(&request, response, afresh, entries);
            }
            (_, ListingsBody::Error { .. }) => self.missed(),
            _ => self.refuse("the answer is not one to the request".into()),
        }
    }

    /// The node didn't answer the request waiting for one. As `FeedSync`'s.
    pub(crate) fn no_answer(&mut self) {
        if self.asked.take().is_some() {
            self.afresh = false;
            self.missed();
        }
    }

    /// A push from the node's watch on this range, applied to `entries` if
    /// taken. As `FeedSync`'s; the addresses it changes also go to
    /// [`Entries::touched`].
    pub(crate) fn push(&mut self, push: &ChangesResponse, entries: &mut impl Entries) -> Pushed {
        let allowance = self.allowance();
        if self.phase != Phase::Following
            || push.epoch != self.epoch
            || push.head <= self.head
            || check_push(self.range, push).is_err()
            || PAGE.saturating_mul(self.pages + 1 + usize::from(!self.answered)) > allowance
        {
            return Pushed::Ignored;
        }
        let (count, set_hash) = self.with_changes(&push.changes, entries);
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
        let touched = self.apply(&push.changes, entries);
        self.head = push.head;
        Pushed::Applied(touched)
    }

    /// End the round, at the caller's deadline. As `FeedSync`'s.
    pub(crate) fn stop(&mut self) {
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

    /// Follow another range. As `FeedSync`'s: entries outside it leave
    /// `entries`, each going to [`Entries::touched`], in address order.
    pub(crate) fn rescope(&mut self, range: AddressRange, entries: &mut impl Entries) {
        let mut from = Bound::Unbounded;
        loop {
            let chunk = entries.scan(from, [0xff; 32], SCAN);
            let Some(&last) = chunk.last() else {
                break;
            };
            for address in chunk.iter().filter(|address| !range.contains(address)) {
                self.remove(address, entries);
            }
            if chunk.len() < SCAN {
                break;
            }
            from = Bound::Excluded(last);
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
    }

    /// Whether the node's copies count. As `FeedSync`'s.
    #[must_use]
    pub(crate) fn in_sync(&self) -> bool {
        self.answered
            && self.phase == Phase::Following
            && self.reported.is_some_and(|report| {
                report.epoch == self.epoch && report.head == self.head && self.matches(&report)
            })
    }

    /// How the round stands. As `FeedSync`'s.
    #[must_use]
    pub(crate) fn outcome(&self) -> Option<FeedOutcome> {
        if self.in_sync() {
            Some(FeedOutcome::Synced)
        } else {
            self.ended
        }
    }

    /// Why the node's last answer was refused. As `FeedSync`'s.
    #[must_use]
    pub(crate) fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Whether a request is waiting for its answer.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn waiting(&self) -> bool {
        self.asked.is_some()
    }

    /// Whether nothing waits for an answer and nothing more can be asked
    /// this round.
    #[must_use]
    pub(crate) fn idle(&self) -> bool {
        self.asked.is_none() && (self.ended.is_some() || self.in_sync() || !self.may_ask())
    }

    /// The pages the node answered this round, each push counting as one.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pages(&self) -> usize {
        self.pages
    }

    /// The range followed.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn range(&self) -> AddressRange {
        self.range
    }

    /// The epoch the mirror follows: 0 before it first follows one.
    #[must_use]
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of the last record the mirror reflects.
    #[must_use]
    pub(crate) fn head(&self) -> u64 {
        self.head
    }

    /// How many entries the mirror holds.
    #[must_use]
    pub(crate) fn len(&self) -> u64 {
        self.count
    }

    /// Whether it holds none.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The set hash of the entries the mirror holds.
    #[must_use]
    pub(crate) fn set_hash(&self) -> SetHash {
        self.set_hash
    }

    /// The node's latest view hash, from its last answer or push.
    #[must_use]
    pub(crate) fn view(&self) -> Option<[u8; 32]> {
        self.view
    }

    /// The node's nearest peers, from its last answer that listed them.
    #[must_use]
    pub(crate) fn peers(&self) -> Option<&[[u8; 32]]> {
        self.peers.as_deref()
    }

    fn take_changes(
        &mut self,
        request: &ChangesRequest,
        response: ChangesResponse,
        afresh: bool,
        entries: &mut impl Entries,
    ) {
        let page = match check_changes_page(request, &response) {
            Ok(page) => page,
            Err(e) => {
                self.refuse(e.to_string());
                return;
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
            self.replace(None, self.range.last(), Vec::new(), entries);
            return;
        }
        match page {
            ChangesPage::Restart { epoch, head } => {
                self.phase = Phase::Reading {
                    epoch,
                    head,
                    cursor: None,
                };
            }
            ChangesPage::Follows(_) => {
                self.apply(&changes, entries);
                self.head = self.head.max(next);
                self.read_afresh_if_wrong();
            }
        }
    }

    fn take_range(
        &mut self,
        request: &RangeListRequest,
        response: RangeListResponse,
        afresh: bool,
        entries: &mut impl Entries,
    ) {
        let Phase::Reading { epoch, head, .. } = self.phase else {
            return;
        };
        let next = match check_range_page(request, &response) {
            Ok(next) => next,
            Err(e) => {
                self.refuse(e.to_string());
                return;
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
        self.replace(request.after, through, response.entries, entries);
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
        report.count == self.count && report.set_hash == self.set_hash
    }

    fn allowance(&self) -> usize {
        WALK_FREE_LISTINGS.saturating_add(WALK_PER_BACKED.saturating_mul(self.backed))
    }

    /// Whether the node may be asked another page this round.
    fn may_ask(&self) -> bool {
        !self.answered
            || (PAGE.saturating_mul(self.pages + 1) <= self.allowance() && self.has_room())
    }

    /// Whether the mirror has room within the allowance for a full page of
    /// new addresses.
    fn has_room(&self) -> bool {
        usize::try_from(self.count)
            .unwrap_or(usize::MAX)
            .saturating_add(PAGE)
            <= self.allowance()
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

    /// Apply the records after the mirror's head, in order. Returns the
    /// addresses whose entries changed.
    fn apply(&mut self, changes: &[FeedChange], entries: &mut impl Entries) -> Vec<XorName> {
        let head = self.head;
        let mut touched = Vec::new();
        for change in changes.iter().filter(|change| change.seq() > head) {
            let changed = match change {
                FeedChange::Entry { entry, .. } => self.put(*entry, entries),
                FeedChange::Removed { address, .. } => self.remove(address, entries),
            };
            if changed {
                touched.push(change.address());
            }
        }
        touched
    }

    /// The count and set hash the mirror would have with `changes` applied,
    /// one per address.
    fn with_changes(&self, changes: &[FeedChange], entries: &impl Entries) -> (u64, SetHash) {
        let mut count = self.count;
        let mut set_hash = self.set_hash;
        for change in changes.iter().filter(|change| change.seq() > self.head) {
            if let Some(old) = entries.get(&change.address()) {
                count = count.saturating_sub(1);
                set_hash.remove(&old);
            }
            if let Some(entry) = change.entry() {
                count += 1;
                set_hash.insert(entry);
            }
        }
        (count, set_hash)
    }

    /// Make the mirror hold `fresh` and nothing else after `after` (or from
    /// the range's start) through `through`. The addresses that go are read
    /// a chunk at a time, so this holds no more of the mirror than a chunk.
    fn replace(
        &mut self,
        after: Option<XorName>,
        through: XorName,
        fresh: Vec<DigestEntry>,
        entries: &mut impl Entries,
    ) {
        if !after.is_some_and(|after| after >= through) {
            let kept: HashSet<XorName> = fresh.iter().map(|entry| entry.address).collect();
            let mut from = after.map_or(Bound::Included(self.range.first()), Bound::Excluded);
            loop {
                let chunk = entries.scan(from, through, SCAN);
                let Some(&last) = chunk.last() else {
                    break;
                };
                for address in chunk.iter().filter(|address| !kept.contains(*address)) {
                    self.remove(address, entries);
                }
                if chunk.len() < SCAN {
                    break;
                }
                from = Bound::Excluded(last);
            }
        }
        for entry in fresh {
            self.put(entry, entries);
        }
    }

    /// Hold `entry` for its address. Returns whether the mirror changed.
    fn put(&mut self, entry: DigestEntry, entries: &mut impl Entries) -> bool {
        match entries.get(&entry.address) {
            Some(old) if old == entry => return false,
            Some(old) => self.set_hash.remove(&old),
            None => self.count += 1,
        }
        self.set_hash.insert(&entry);
        entries.insert(entry);
        entries.touched(entry.address);
        true
    }

    /// Hold nothing for `address`. Returns whether the mirror changed.
    fn remove(&mut self, address: &XorName, entries: &mut impl Entries) -> bool {
        let Some(old) = entries.get(address) else {
            return false;
        };
        self.set_hash.remove(&old);
        self.count = self.count.saturating_sub(1);
        entries.delete(address);
        entries.touched(*address);
        true
    }
}

/// A mirror's entries in memory, with the addresses touched in order: for
/// tests.
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub(crate) struct MemEntries {
    pub(crate) held: std::collections::BTreeMap<XorName, DigestEntry>,
    pub(crate) touched: Vec<XorName>,
}

#[cfg(test)]
impl Entries for MemEntries {
    fn get(&self, address: &XorName) -> Option<DigestEntry> {
        self.held.get(address).copied()
    }

    fn insert(&mut self, entry: DigestEntry) {
        self.held.insert(entry.address, entry);
    }

    fn delete(&mut self, address: &XorName) {
        self.held.remove(address);
    }

    fn scan(&self, from: Bound<XorName>, through: XorName, limit: usize) -> Vec<XorName> {
        if let Bound::Excluded(after) | Bound::Included(after) = from {
            if after > through {
                return Vec::new();
            }
        }
        self.held
            .range((from, Bound::Included(through)))
            .map(|(address, _)| *address)
            .take(limit)
            .collect()
    }

    fn touched(&mut self, address: XorName) {
        self.touched.push(address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_listings::{view_hash, FeedSync};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::{BTreeMap, HashMap};

    /// A node, as a change feed, for both mirrors to follow.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Behaviour {
        Honest,
        /// Makes up new entries before each answer, so it always has more.
        Flood,
        /// Gives a set hash that never matches what it serves.
        WrongHash,
        /// Answers with addresses outside the range asked about.
        OutOfRange,
        /// Answers some requests with nothing, some with an error.
        Flaky,
        /// Answers some requests with an answer of the wrong kind.
        WrongKind,
    }

    struct Node {
        behaviour: Behaviour,
        epoch: u64,
        head: u64,
        rows: BTreeMap<u64, FeedChange>,
        seq_of: HashMap<XorName, u64>,
        served: BTreeMap<XorName, DigestEntry>,
        peers: Vec<[u8; 32]>,
        made_up: u64,
    }

    fn address(rng: &mut StdRng, range: AddressRange, inside: bool) -> XorName {
        let mut address: XorName = rng.gen();
        let bits = usize::from(range.bits());
        let prefix = range.prefix();
        for bit in 0..bits {
            let mask = 0x80u8 >> (bit % 8);
            address[bit / 8] = (address[bit / 8] & !mask) | (prefix[bit / 8] & mask);
        }
        if !inside && bits > 0 {
            address[0] ^= 0x80;
        }
        address
    }

    fn entry(address: XorName, rng: &mut StdRng) -> DigestEntry {
        DigestEntry {
            address,
            time: 1_791_000_000 + rng.gen_range(0..1_000),
            block_number: 81_950_000 + rng.gen_range(0..1_000),
            log_index: rng.gen_range(0..2),
            first_seen: rng.gen_bool(0.5).then_some(1_791_320_400),
            digest: [rng.gen_range(0..3u8); 32],
        }
    }

    impl Node {
        fn new(behaviour: Behaviour, rng: &mut StdRng) -> Self {
            Self {
                behaviour,
                epoch: rng.gen_range(1..4),
                head: 0,
                rows: BTreeMap::new(),
                seq_of: HashMap::new(),
                served: BTreeMap::new(),
                peers: (0..rng.gen_range(0..4)).map(|_| rng.gen()).collect(),
                made_up: 0,
            }
        }

        fn record(&mut self, address: XorName, entry: Option<DigestEntry>) {
            self.head += 1;
            let seq = self.head;
            if let Some(old) = self.seq_of.insert(address, seq) {
                self.rows.remove(&old);
            }
            let change = match entry {
                Some(entry) => {
                    self.served.insert(address, entry);
                    FeedChange::Entry { seq, entry }
                }
                None => {
                    self.served.remove(&address);
                    FeedChange::Removed { seq, address }
                }
            };
            self.rows.insert(seq, change);
        }

        /// Change what it serves at random, mostly within `range`.
        fn churn(&mut self, rng: &mut StdRng, range: AddressRange, changes: usize) {
            for _ in 0..changes {
                let known: Vec<XorName> = self.served.keys().copied().collect();
                if !known.is_empty() && rng.gen_bool(0.3) {
                    let at = known[rng.gen_range(0..known.len())];
                    if rng.gen_bool(0.5) {
                        self.record(at, None);
                    } else {
                        let changed = entry(at, rng);
                        self.record(at, Some(changed));
                    }
                } else {
                    let inside = rng.gen_bool(0.95);
                    let at = address(rng, range, inside);
                    let fresh = entry(at, rng);
                    self.record(at, Some(fresh));
                }
            }
        }

        /// Number what it serves afresh, as after a wipe or a new store.
        fn renumber(&mut self, epoch: u64, rng: &mut StdRng) {
            self.epoch = epoch;
            self.head = 0;
            self.rows.clear();
            self.seq_of.clear();
            if rng.gen_bool(0.3) {
                self.served.clear();
            }
            let served: Vec<DigestEntry> = self.served.values().copied().collect();
            for entry in served {
                self.record(entry.address, Some(entry));
            }
        }

        fn totals(&self, range: AddressRange) -> (u64, SetHash) {
            let held: Vec<&DigestEntry> = self
                .served
                .values()
                .filter(|entry| range.contains(&entry.address))
                .collect();
            (held.len() as u64, SetHash::of(held))
        }

        fn answer(&mut self, body: &ListingsBody, rng: &mut StdRng) -> Option<ListingsBody> {
            if self.behaviour == Behaviour::Flaky && rng.gen_bool(0.3) {
                return if rng.gen_bool(0.5) {
                    None
                } else {
                    Some(ListingsBody::Error {
                        message: "busy".into(),
                    })
                };
            }
            if self.behaviour == Behaviour::WrongKind && rng.gen_bool(0.2) {
                return Some(ListingsBody::ListResponse {
                    listings: Vec::new(),
                    more: false,
                });
            }
            match body {
                ListingsBody::ChangesRequest(request) => {
                    Some(ListingsBody::ChangesResponse(self.changes(request, rng)))
                }
                ListingsBody::RangeListRequest(request) => Some(ListingsBody::RangeListResponse(
                    self.range_list(request, rng),
                )),
                _ => None,
            }
        }

        fn changes(&mut self, request: &ChangesRequest, rng: &mut StdRng) -> ChangesResponse {
            let range = request.range();
            if self.behaviour == Behaviour::Flood {
                for _ in 0..rng.gen_range(100..400) {
                    self.made_up += 1;
                    let at = address(rng, range, true);
                    let fresh = entry(at, rng);
                    self.record(at, Some(fresh));
                }
            }
            let (count, mut set_hash) = self.totals(range);
            if self.behaviour == Behaviour::WrongHash {
                set_hash.insert(&entry([0xee; 32], rng));
            }
            let view = view_hash(&self.peers);
            let peers = if request.want_peers {
                self.peers.clone()
            } else {
                Vec::new()
            };
            if request.epoch != self.epoch || request.after > self.head {
                return ChangesResponse {
                    epoch: self.epoch,
                    head: self.head,
                    next: self.head,
                    count,
                    set_hash,
                    changes: Vec::new(),
                    more: false,
                    view,
                    peers,
                };
            }
            let limit = request.limit.min(MAX_LIST_LIMIT) as usize;
            let reads = rng.gen_range(1..600);
            let mut changes = Vec::new();
            let mut next = request.after;
            for (read, (&seq, change)) in self.rows.range(request.after + 1..).enumerate() {
                let inside = range.contains(&change.address());
                if inside || self.behaviour == Behaviour::OutOfRange {
                    if changes.len() == limit {
                        break;
                    }
                    changes.push(*change);
                }
                next = seq;
                if read + 1 == reads {
                    break;
                }
            }
            ChangesResponse {
                epoch: self.epoch,
                head: self.head,
                next,
                count,
                set_hash,
                changes,
                more: next < self.head,
                view,
                peers,
            }
        }

        fn range_list(&self, request: &RangeListRequest, rng: &mut StdRng) -> RangeListResponse {
            let range = request.range();
            let limit = (request.limit.min(MAX_LIST_LIMIT) as usize).min(rng.gen_range(1..300));
            let from = request
                .after
                .map_or(Bound::Included(range.first()), Bound::Excluded);
            let mut entries: Vec<DigestEntry> = self
                .served
                .range((from, Bound::Included(range.last())))
                .map(|(_, entry)| *entry)
                .take(limit + 1)
                .collect();
            let more = entries.len() > limit;
            entries.truncate(limit);
            if self.behaviour == Behaviour::OutOfRange && rng.gen_bool(0.3) {
                let outside = address(rng, range, false);
                entries.insert(0, entry(outside, rng));
                entries.truncate(limit);
            }
            RangeListResponse { entries, more }
        }

        /// A push of the records in `range` after `after`: its last few, or
        /// one that skips a record.
        fn push(&self, range: AddressRange, after: u64, rng: &mut StdRng) -> ChangesResponse {
            let (count, set_hash) = self.totals(range);
            let mut changes: Vec<FeedChange> = self
                .rows
                .range(after + 1..)
                .map(|(_, change)| *change)
                .filter(|change| range.contains(&change.address()))
                .collect();
            if !changes.is_empty() && rng.gen_bool(0.2) {
                changes.remove(0);
            }
            changes.truncate(PAGE);
            ChangesResponse {
                epoch: self.epoch,
                head: self.head,
                next: self.head,
                count,
                set_hash,
                changes,
                more: false,
                view: view_hash(&self.peers),
                peers: Vec::new(),
            }
        }
    }

    /// Check that `ours` and `theirs` stand the same, holding the same
    /// entries.
    fn same(ours: &MirrorSync, held: &MemEntries, theirs: &FeedSync, step: &str) {
        assert_eq!(ours.in_sync(), theirs.in_sync(), "in_sync, {step}");
        assert_eq!(ours.outcome(), theirs.outcome(), "outcome, {step}");
        assert_eq!(ours.problem(), theirs.problem(), "problem, {step}");
        assert_eq!(ours.waiting(), theirs.waiting(), "waiting, {step}");
        assert_eq!(ours.idle(), theirs.idle(), "idle, {step}");
        assert_eq!(ours.pages(), theirs.pages(), "pages, {step}");
        assert_eq!(ours.range(), theirs.range(), "range, {step}");
        assert_eq!(ours.epoch(), theirs.epoch(), "epoch, {step}");
        assert_eq!(ours.head(), theirs.head(), "head, {step}");
        assert_eq!(ours.len(), theirs.len() as u64, "len, {step}");
        assert_eq!(ours.is_empty(), theirs.is_empty(), "is_empty, {step}");
        assert_eq!(ours.set_hash(), theirs.set_hash(), "set_hash, {step}");
        assert_eq!(ours.view(), theirs.view(), "view, {step}");
        assert_eq!(ours.peers(), theirs.peers(), "peers, {step}");
        let theirs_held: Vec<DigestEntry> = theirs.entries().copied().collect();
        let ours_held: Vec<DigestEntry> = held.held.values().copied().collect();
        assert_eq!(ours_held, theirs_held, "entries, {step}");
    }

    /// A range of `bits` leading bits, at random.
    fn range(rng: &mut StdRng, bits: u8) -> AddressRange {
        AddressRange::new(rng.gen(), bits)
    }

    /// What the runs of [`agree`] went through, so a test can check that
    /// it saw each path it means to.
    #[derive(Debug, Default)]
    struct Seen {
        /// How rounds ended, by outcome.
        outcomes: HashMap<Option<FeedOutcome>, usize>,
        /// Pushes taken, behind and left alone.
        applied: usize,
        behind: usize,
        ignored: usize,
        /// Answers that changed some entry, and that emptied the mirror.
        changed: usize,
        emptied: usize,
        renumbered: usize,
        rescoped: usize,
        resumed: usize,
    }

    /// Drive a `MirrorSync` and a `FeedSync` through `rounds` rounds of a
    /// node behaving as `behaviour`, with pushes, deadlines, new epochs,
    /// rescoping and changing allowances, checking after every step that
    /// they agree. What the run went through goes into `seen`.
    fn agree(seed: u64, behaviour: Behaviour, rounds: usize, seen: &mut Seen) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut bits = rng.gen_range(0..3u8);
        let mut followed = range(&mut rng, bits);
        let mut node = Node::new(behaviour, &mut rng);
        let changes = rng.gen_range(0..2_000);
        node.churn(&mut rng, followed, changes);
        let resumed = rng.gen_bool(0.3);
        seen.resumed += usize::from(resumed);
        let (mut theirs, mut ours, mut held) = if resumed {
            // Kept from an earlier run: some of what the node served, at a
            // head it may since have passed, maybe in another epoch.
            let kept: Vec<DigestEntry> = node
                .served
                .values()
                .filter(|entry| followed.contains(&entry.address))
                .filter(|_| rng.gen_bool(0.8))
                .copied()
                .collect();
            let epoch = if rng.gen_bool(0.8) { node.epoch } else { 0 };
            let head = rng.gen_range(0..=node.head);
            let theirs = FeedSync::resume(followed, epoch, head, kept.iter().copied());
            let held = MemEntries {
                held: kept.iter().map(|entry| (entry.address, *entry)).collect(),
                touched: Vec::new(),
            };
            let ours = MirrorSync::resume(
                followed,
                epoch,
                head,
                kept.len() as u64,
                SetHash::of(kept.iter()),
            );
            (theirs, ours, held)
        } else {
            (
                FeedSync::new(followed),
                MirrorSync::new(followed),
                MemEntries::default(),
            )
        };
        same(&ours, &held, &theirs, "start");
        for round in 0..rounds {
            let backed = if rng.gen_bool(0.3) {
                rng.gen_range(0..5_000)
            } else {
                0
            };
            theirs.begin_round();
            theirs.set_backed(backed);
            ours.begin_round();
            ours.set_backed(backed);
            let want_peers = rng.gen_bool(0.3);
            let mut steps = 0;
            loop {
                steps += 1;
                let step = format!("seed {seed}, round {round}, step {steps}");
                // Pushes can come before or after an answer.
                if rng.gen_bool(0.2) {
                    let push = node.push(followed, ours.head(), &mut rng);
                    held.touched.clear();
                    let pushed_ours = ours.push(&push, &mut held);
                    let pushed_theirs = theirs.push(&push);
                    assert_eq!(pushed_ours, pushed_theirs, "push, {step}");
                    match pushed_ours {
                        Pushed::Applied(_) => seen.applied += 1,
                        Pushed::Behind => seen.behind += 1,
                        Pushed::Ignored => seen.ignored += 1,
                    }
                    let reported = match &pushed_theirs {
                        Pushed::Applied(touched) => touched.clone(),
                        _ => Vec::new(),
                    };
                    assert_eq!(held.touched, reported, "push touched, {step}");
                    same(&ours, &held, &theirs, &step);
                }
                let request_ours = ours.next_request(want_peers, true);
                let request_theirs = theirs.next_request(want_peers, true);
                assert_eq!(request_ours, request_theirs, "request, {step}");
                same(&ours, &held, &theirs, &step);
                let Some(request) = request_ours else {
                    break;
                };
                if steps > 60 || rng.gen_bool(0.02) {
                    // The caller's deadline.
                    ours.stop();
                    theirs.stop();
                    same(&ours, &held, &theirs, &step);
                    break;
                }
                if rng.gen_bool(0.1) {
                    let changes = rng.gen_range(1..50);
                    node.churn(&mut rng, followed, changes);
                }
                match node.answer(&request, &mut rng) {
                    Some(body) => {
                        held.touched.clear();
                        ours.answer(body.clone(), &mut held);
                        let had = theirs.len();
                        let touched = theirs.answer(body);
                        assert_eq!(held.touched, touched, "touched, {step}");
                        seen.changed += usize::from(!touched.is_empty());
                        seen.emptied += usize::from(had > 0 && theirs.is_empty());
                    }
                    None => {
                        ours.no_answer();
                        theirs.no_answer();
                    }
                }
                same(&ours, &held, &theirs, &step);
            }
            ours.stop();
            theirs.stop();
            same(
                &ours,
                &held,
                &theirs,
                &format!("seed {seed}, round {round}, end"),
            );
            *seen.outcomes.entry(theirs.outcome()).or_default() += 1;
            // Between rounds: the node changes, restarts its feed, or the
            // mirror follows another range.
            let changes = rng.gen_range(0..300);
            node.churn(&mut rng, followed, changes);
            if rng.gen_bool(0.05) {
                let epoch = node.epoch + 1;
                node.renumber(epoch, &mut rng);
                seen.renumbered += 1;
            }
            if rng.gen_bool(0.1) {
                let wider = rng.gen_bool(0.5) && bits > 0;
                bits = if wider { bits - 1 } else { (bits + 1).min(4) };
                let next = if rng.gen_bool(0.8) {
                    AddressRange::new(followed.prefix(), bits)
                } else {
                    range(&mut rng, bits)
                };
                held.touched.clear();
                ours.rescope(next, &mut held);
                seen.rescoped += 1;
                let touched = theirs.rescope(next);
                assert_eq!(held.touched, touched, "rescope touched, seed {seed}");
                followed = next;
                same(&ours, &held, &theirs, &format!("seed {seed}, rescope"));
            }
        }
    }

    #[test]
    fn a_mirror_kept_outside_follows_a_feed_as_feed_sync_does() {
        let mut seen = Seen::default();
        for seed in 0..40 {
            agree(seed, Behaviour::Honest, 12, &mut seen);
        }
        // Every path of an honest node was taken: in sync, out of time and
        // out of allowance; pushes taken, behind and left alone; restarts,
        // rescoping and resuming.
        for outcome in [
            Some(FeedOutcome::Synced),
            Some(FeedOutcome::Deadline),
            Some(FeedOutcome::Budget),
        ] {
            assert!(seen.outcomes.contains_key(&outcome), "{seen:?}");
        }
        assert!(
            seen.applied > 0 && seen.behind > 0 && seen.ignored > 0,
            "{seen:?}"
        );
        assert!(seen.changed > 0 && seen.renumbered > 0, "{seen:?}");
        assert!(seen.rescoped > 0 && seen.resumed > 0, "{seen:?}");
    }

    #[test]
    fn faulty_nodes_are_followed_as_feed_sync_follows_them() {
        let faults = [
            Behaviour::Flood,
            Behaviour::WrongHash,
            Behaviour::OutOfRange,
            Behaviour::Flaky,
            Behaviour::WrongKind,
        ];
        let mut seen = Seen::default();
        for (n, behaviour) in faults.into_iter().enumerate() {
            for seed in 0..12 {
                agree(1_000 * (n as u64 + 1) + seed, behaviour, 10, &mut seen);
            }
        }
        // Refused answers, nodes that stopped answering, nodes held to their
        // allowance, and mirrors started again from nothing.
        for outcome in [
            Some(FeedOutcome::BadPage),
            Some(FeedOutcome::NoAnswer),
            Some(FeedOutcome::Budget),
        ] {
            assert!(seen.outcomes.contains_key(&outcome), "{seen:?}");
        }
        assert!(seen.emptied > 0, "{seen:?}");
    }

    #[test]
    fn a_scan_reads_only_what_was_asked() {
        let mut held = MemEntries::default();
        let mut rng = StdRng::seed_from_u64(9);
        for n in 0..10u8 {
            let mut at = [0u8; 32];
            at[0] = n * 10;
            held.insert(entry(at, &mut rng));
        }
        let first = |n: u8| {
            let mut at = [0u8; 32];
            at[0] = n;
            at
        };
        assert_eq!(
            held.scan(Bound::Included(first(10)), first(40), 2),
            [first(10), first(20)]
        );
        assert_eq!(
            held.scan(Bound::Excluded(first(10)), first(40), 9),
            [first(20), first(30), first(40)]
        );
        assert!(held
            .scan(Bound::Excluded(first(50)), first(40), 9)
            .is_empty());
    }
}
