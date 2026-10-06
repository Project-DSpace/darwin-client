//! Walking every node's index in one read, with no ceiling on how much the
//! index holds.
//!
//! A node's pages are only shape-checked ([`check_list_page`]), so a node can
//! serve as many made-up listings as it likes, and a fixed cap on what one
//! walk takes from a node would cap the index too. [`IndexWalk`] reads each
//! node for as long as other nodes back what it sends instead: a node gets
//! [`WALK_FREE_LISTINGS`] listings' worth of pages, and [`WALK_PER_BACKED`]
//! more for each listing it sends whose address a quorum of its nearest nodes
//! serve. A node holding real listings earns as it goes and its walk runs to
//! the end; one serving listings nobody else has stops after a few pages. A
//! walk stopped early, by this or by the caller's deadline, gives a key to
//! resume it from in the next read ([`NodeReport::resume`]).
//!
//! An address's support ([`AddressWalk::support`]) is how many of the
//! [`NEAREST_NODES`] nodes nearest it serve some listing for it. Do
//! per-address work, such as fetching the envelope or reading the chain, only
//! where support reaches [`QUORUM_THRESHOLD`]: nodes fewer than a quorum,
//! however they collude, then cost nothing beyond their pages.
//!
//! Nothing here does I/O. The caller sends each request
//! [`IndexWalk::next_requests`] gives, passes back each page with
//! [`IndexWalk::answer`] or the lack of one with [`IndexWalk::no_answer`],
//! and calls [`IndexWalk::finish`] once nothing is left to ask
//! ([`IndexWalk::idle`]) or after [`IndexWalk::stop`] at its deadline.

use crate::listing::{Listing, ListingKey};
use crate::message::{check_list_page, MAX_LIST_LIMIT};
use crate::payment::QUORUM_THRESHOLD;
use ant_protocol::{XorName, CLOSE_GROUP_SIZE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

/// How many nodes nearest an address count towards its support: a close
/// group.
pub const NEAREST_NODES: usize = CLOSE_GROUP_SIZE;

/// Listings' worth of pages every node is read for before it must earn more:
/// eight full pages.
pub const WALK_FREE_LISTINGS: usize = 2_048;

/// Listings' worth of pages a node earns for each listing it sends whose
/// address a quorum of the nodes nearest it serve.
pub const WALK_PER_BACKED: usize = 2;

/// How near an address a node must be to earn from it: among this many of
/// the nodes nearest it. Nodes keep listings for a while after other nodes
/// come closer, so this is wider than a close group; only the nearest
/// [`NEAREST_NODES`] count towards support.
pub const WALK_EARNING_RANKS: usize = 20;

/// A node that doesn't answer a request is asked again once per walk, and
/// once more for every this many pages it has answered.
pub const WALK_RETRY_PAGES: usize = 64;

/// The listings a full page counts for, against a node's allowance, however
/// few it holds.
const PAGE: usize = MAX_LIST_LIMIT as usize;

/// How one node's walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkOutcome {
    /// It reached the end of the node's index.
    Complete,
    /// The node had sent as many pages as it had earned: the rest waits for
    /// the next read.
    Budget,
    /// The caller stopped it ([`IndexWalk::stop`]) before the end.
    Deadline,
    /// The node stopped answering, or never answered.
    NoAnswer,
    /// The node sent a page [`check_list_page`] refuses.
    BadPage,
}

/// One node's walk, at its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeReport<P> {
    /// The node.
    pub peer: P,
    /// How the walk ended.
    pub outcome: WalkOutcome,
    /// Why a page was refused, for [`WalkOutcome::BadPage`].
    pub problem: Option<String>,
    /// Where the walk began.
    pub from: ListingKey,
    /// Where it stopped: the `from` its next request would have had. `None`
    /// if it reached the end of the node's index.
    pub reached: Option<ListingKey>,
    /// When its first request was sent, by the caller's clock (Unix
    /// seconds). `None` if none was.
    pub began: Option<u64>,
    /// Pages the node answered.
    pub pages: usize,
    /// Listings those pages held.
    pub listings: usize,
    /// Listings it sent whose addresses reached a quorum of their nearest
    /// nodes, once per address, counted only where it is among the
    /// [`WALK_EARNING_RANKS`] nodes nearest.
    pub backed: usize,
}

impl<P> NodeReport<P> {
    /// Where to walk this node from in the next read to carry on: for a walk
    /// stopped before the end after at least one page. `None` for a complete
    /// walk, a node that never answered, or one that sent a bad page: the
    /// next read walks those from the start.
    #[must_use]
    pub fn resume(&self) -> Option<ListingKey> {
        match self.outcome {
            WalkOutcome::Budget | WalkOutcome::Deadline | WalkOutcome::NoAnswer
                if self.pages > 0 =>
            {
                self.reached
            }
            _ => None,
        }
    }

    /// Whether the walk passed `key`, so that it returned whatever listing
    /// the node held there when the walk got to it.
    #[must_use]
    pub fn covered(&self, key: &ListingKey) -> bool {
        self.pages > 0 && self.from <= *key && self.reached.is_none_or(|reached| *key < reached)
    }
}

/// What a walk found for one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressWalk<P> {
    /// The address.
    pub address: XorName,
    /// The nodes nearest it of those walked, nearest first:
    /// [`NEAREST_NODES`] of them, or all of them if fewer, whether or not
    /// they answered.
    pub nearest: Vec<P>,
    /// The copies those nodes sent, one per node, in the order they came in.
    /// Left out, as [`merge_copies`](crate::merge_copies) leaves them out:
    /// copies that fail [`Listing::validate`], and every copy of a node that
    /// sent two different ones. Copies from nodes not in `nearest` are left
    /// out too.
    pub copies: Vec<(P, Listing)>,
    /// How many of `nearest` serve some listing for the address: the number
    /// of nodes in `copies`.
    pub support: usize,
}

/// What a walk found, from [`IndexWalk::finish`].
#[derive(Debug, Clone)]
pub struct WalkResult<P> {
    /// Each address at least one of its nearest nodes served, in no
    /// particular order.
    pub addresses: Vec<AddressWalk<P>>,
    /// Each node's walk, in the order the nodes were given.
    pub nodes: Vec<NodeReport<P>>,
    ids: Vec<[u8; 32]>,
}

impl<P: Clone> WalkResult<P> {
    /// The nodes nearest `address` of those walked, nearest first:
    /// [`NEAREST_NODES`] of them, or all of them if fewer.
    #[must_use]
    pub fn nearest_to(&self, address: &XorName) -> Vec<P> {
        nearest_by_distance(address, &self.ids, NEAREST_NODES)
            .into_iter()
            .map(|index| self.nodes[index].peer.clone())
            .collect()
    }
}

/// The indexes into `ids` of the `count` ids nearest `address` by XOR
/// distance, nearest first, or of all of them if there are fewer. Equal ids
/// keep their order in `ids`.
#[must_use]
pub fn nearest_by_distance(address: &XorName, ids: &[[u8; 32]], count: usize) -> Vec<usize> {
    let distance = |index: usize| {
        let mut distance = [0u8; 32];
        for (byte, (a, b)) in distance.iter_mut().zip(address.iter().zip(&ids[index])) {
            *byte = a ^ b;
        }
        (distance, index)
    };
    let mut order: Vec<usize> = (0..ids.len()).collect();
    if count < order.len() {
        order.select_nth_unstable_by_key(count, |&index| distance(index));
        order.truncate(count);
    }
    order.sort_unstable_by_key(|&index| distance(index));
    order
}

/// Walks every node's index at once, for one read. See the module docs.
#[derive(Debug, Clone)]
pub struct IndexWalk<P> {
    nodes: Vec<NodeState<P>>,
    index_of: HashMap<P, usize>,
    ids: Vec<[u8; 32]>,
    addresses: HashMap<XorName, AddressState>,
    quorum: usize,
}

#[derive(Debug, Clone)]
struct NodeState<P> {
    peer: P,
    from: ListingKey,
    next: ListingKey,
    pages: usize,
    listings: usize,
    backed: usize,
    retries: usize,
    waiting: bool,
    began: Option<u64>,
    ended: Option<WalkOutcome>,
    problem: Option<String>,
}

impl<P> NodeState<P> {
    /// Whether the node has earned another page.
    fn within_allowance(&self) -> bool {
        PAGE.saturating_mul(self.pages + 1)
            <= WALK_FREE_LISTINGS.saturating_add(WALK_PER_BACKED.saturating_mul(self.backed))
    }

    /// Whether it can be sent a request now.
    fn ready(&self) -> bool {
        self.ended.is_none() && !self.waiting && self.within_allowance()
    }
}

#[derive(Debug, Clone)]
struct AddressState {
    /// The nodes nearest the address, as indexes, nearest first, up to
    /// [`WALK_EARNING_RANKS`].
    ranked: Vec<usize>,
    /// The first valid copy from each of the [`NEAREST_NODES`] nearest that
    /// sent one, in the order they came in; `None` once the node sent a
    /// different one.
    copies: Vec<(usize, Option<Listing>)>,
    /// Nodes among `ranked` that sent a valid copy, each once.
    senders: Vec<usize>,
    /// How many of `copies` are `Some`.
    support: usize,
    /// Whether support has reached the quorum.
    backed: bool,
}

impl<P: Clone + Eq + Hash> IndexWalk<P> {
    /// A walk of `nodes`: each node, its 32-byte id in the address space
    /// (nearness to an address is XOR distance from it), and the key to walk
    /// it from. A node given twice is walked once, from its first key. The
    /// quorum is [`QUORUM_THRESHOLD`].
    pub fn new(nodes: impl IntoIterator<Item = (P, [u8; 32], ListingKey)>) -> Self {
        let mut walk = Self {
            nodes: Vec::new(),
            index_of: HashMap::new(),
            ids: Vec::new(),
            addresses: HashMap::new(),
            quorum: QUORUM_THRESHOLD,
        };
        for (peer, id, from) in nodes {
            if walk.index_of.contains_key(&peer) {
                continue;
            }
            walk.index_of.insert(peer.clone(), walk.nodes.len());
            walk.ids.push(id);
            walk.nodes.push(NodeState {
                peer,
                from,
                next: from,
                pages: 0,
                listings: 0,
                backed: 0,
                retries: 0,
                waiting: false,
                began: None,
                ended: None,
                problem: None,
            });
        }
        walk
    }

    /// The same walk with `quorum` agreeing nodes in place of
    /// [`QUORUM_THRESHOLD`] (at least 1): only for a test network too small
    /// for a close group.
    #[must_use]
    pub fn with_quorum(mut self, quorum: usize) -> Self {
        self.quorum = quorum.max(1);
        self
    }

    /// How many nodes the walk has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether it has none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The nodes to send their next list request to now, each with the key
    /// to ask from (`ListRequest { from, limit: MAX_LIST_LIMIT }`): at most
    /// `slots` of them, those furthest behind first, so the walks keep pace
    /// and a node's listings meet the copies that earn it more. Each is
    /// marked as waiting for its answer. `now` is the caller's clock, in Unix
    /// seconds.
    pub fn next_requests(&mut self, slots: usize, now: u64) -> Vec<(P, ListingKey)> {
        let mut ready: Vec<usize> = (0..self.nodes.len())
            .filter(|&index| self.nodes[index].ready())
            .collect();
        ready.sort_unstable_by_key(|&index| (self.nodes[index].next, index));
        ready.truncate(slots);
        ready
            .into_iter()
            .map(|index| {
                let node = &mut self.nodes[index];
                node.waiting = true;
                node.began.get_or_insert(now);
                (node.peer.clone(), node.next)
            })
            .collect()
    }

    /// How many requests are waiting for an answer.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.nodes.iter().filter(|node| node.waiting).count()
    }

    /// Whether nothing is waiting for an answer and nothing can be asked:
    /// the walk is over, and [`finish`](Self::finish) gives its result.
    #[must_use]
    pub fn idle(&self) -> bool {
        self.nodes.iter().all(|node| !node.waiting && !node.ready())
    }

    /// How many nodes can't be asked anything more for now: their walks
    /// ended, or they have used what they earned and nothing is waiting for
    /// an answer. For a deadline relative to how long most walks take.
    #[must_use]
    pub fn settled(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| node.ended.is_some() || (!node.waiting && !node.ready()))
            .count()
    }

    /// `peer`'s answer to its last request: a `ListResponse`'s listings and
    /// `more`. A page [`check_list_page`] refuses ends the node's walk. An
    /// answer from a node not waiting for one, such as a walk already
    /// stopped, is ignored.
    pub fn answer(&mut self, peer: &P, listings: Vec<Listing>, more: bool) {
        let Some(&index) = self.index_of.get(peer) else {
            return;
        };
        let node = &mut self.nodes[index];
        if !node.waiting || node.ended.is_some() {
            return;
        }
        node.waiting = false;
        let following = match check_list_page(node.next, MAX_LIST_LIMIT, &listings, more) {
            Ok(following) => following,
            Err(e) => {
                node.ended = Some(WalkOutcome::BadPage);
                node.problem = Some(e.to_string());
                return;
            }
        };
        node.pages += 1;
        node.listings += listings.len();
        match following {
            Some(key) => node.next = key,
            None => node.ended = Some(WalkOutcome::Complete),
        }
        for listing in listings {
            self.add_copy(index, listing);
        }
    }

    /// `peer` didn't answer its last request: it timed out, or the answer
    /// wasn't a page. The node is asked again once per walk, and once more
    /// for every [`WALK_RETRY_PAGES`] pages it has answered; after that its
    /// walk ends.
    pub fn no_answer(&mut self, peer: &P) {
        let Some(&index) = self.index_of.get(peer) else {
            return;
        };
        let node = &mut self.nodes[index];
        if !node.waiting || node.ended.is_some() {
            return;
        }
        node.waiting = false;
        if node.retries < 1 + node.pages / WALK_RETRY_PAGES {
            node.retries += 1;
        } else {
            node.ended = Some(WalkOutcome::NoAnswer);
        }
    }

    /// End every walk still going: for the caller's deadline. A node that
    /// had used what it earned ends as [`WalkOutcome::Budget`], any other as
    /// [`WalkOutcome::Deadline`]. Answers that come in later are ignored.
    pub fn stop(&mut self) {
        for node in &mut self.nodes {
            if node.ended.is_none() {
                node.ended = Some(if !node.waiting && !node.within_allowance() {
                    WalkOutcome::Budget
                } else {
                    WalkOutcome::Deadline
                });
                node.waiting = false;
            }
        }
    }

    /// What the walk found. Walks still going end as by [`stop`](Self::stop).
    #[must_use]
    pub fn finish(mut self) -> WalkResult<P> {
        self.stop();
        let peers: Vec<P> = self.nodes.iter().map(|node| node.peer.clone()).collect();
        let addresses = self
            .addresses
            .into_iter()
            .filter_map(|(address, entry)| {
                let copies: Vec<(P, Listing)> = entry
                    .copies
                    .into_iter()
                    .filter_map(|(node, copy)| copy.map(|copy| (peers[node].clone(), copy)))
                    .collect();
                if copies.is_empty() {
                    return None;
                }
                let nearest = entry
                    .ranked
                    .iter()
                    .take(NEAREST_NODES)
                    .map(|&node| peers[node].clone())
                    .collect();
                Some(AddressWalk {
                    address,
                    nearest,
                    support: copies.len(),
                    copies,
                })
            })
            .collect();
        let nodes = self
            .nodes
            .into_iter()
            .map(|node| {
                let outcome = node.ended.unwrap_or(WalkOutcome::Deadline);
                NodeReport {
                    peer: node.peer,
                    outcome,
                    problem: node.problem,
                    from: node.from,
                    reached: (outcome != WalkOutcome::Complete).then_some(node.next),
                    began: node.began,
                    pages: node.pages,
                    listings: node.listings,
                    backed: node.backed,
                }
            })
            .collect();
        WalkResult {
            addresses,
            nodes,
            ids: self.ids,
        }
    }

    /// Take one listing a node sent. Copies from nodes not among the
    /// [`WALK_EARNING_RANKS`] nearest its address are dropped unread, so a
    /// node's copies for addresses far from it cost nothing but their page.
    fn add_copy(&mut self, node: usize, listing: Listing) {
        let address = listing.address;
        let entry = match self.addresses.get_mut(&address) {
            Some(entry) => entry,
            None => {
                let ranked = nearest_by_distance(&address, &self.ids, WALK_EARNING_RANKS);
                if !ranked.contains(&node) {
                    return;
                }
                self.addresses.entry(address).or_insert(AddressState {
                    ranked,
                    copies: Vec::new(),
                    senders: Vec::new(),
                    support: 0,
                    backed: false,
                })
            }
        };
        let Some(rank) = entry.ranked.iter().position(|&ranked| ranked == node) else {
            return;
        };
        if listing.validate().is_err() {
            return;
        }
        if !entry.senders.contains(&node) {
            entry.senders.push(node);
            if entry.backed {
                self.nodes[node].backed += 1;
            }
        }
        if rank < NEAREST_NODES {
            match entry
                .copies
                .iter_mut()
                .find(|(held_by, _)| *held_by == node)
            {
                None => {
                    entry.copies.push((node, Some(listing)));
                    entry.support += 1;
                }
                Some((_, slot)) => {
                    if slot.as_ref().is_some_and(|held| *held != listing) {
                        *slot = None;
                        entry.support -= 1;
                    }
                }
            }
        }
        if !entry.backed && entry.support >= self.quorum {
            entry.backed = true;
            for &sender in &entry.senders {
                self.nodes[sender].backed += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Metadata;
    use crate::flags::{Flags, PaymentField, ShownFields};
    use crate::listing::ListingPayment;

    const NOW: u64 = 1_800_000_000;

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

    /// A listing in the index showing every field but the quote, paid in
    /// `block`.
    fn real(address: XorName, block: u64) -> Listing {
        Listing {
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
        }
    }

    /// A made-up listing in the index that shows nothing, dated this hour.
    fn fake(address: XorName) -> Listing {
        Listing {
            address,
            flags: Flags {
                shown: ShownFields::NONE,
                in_index: true,
                withheld: false,
            },
            metadata: Metadata::default(),
            size: None,
            payment: ListingPayment::default(),
            first_seen: Some(NOW - NOW % 3_600),
        }
    }

    #[derive(Clone)]
    enum Behaviour {
        /// Serves what it holds, in order.
        Honest,
        /// Serves endless made-up listings at addresses starting with
        /// `prefix`, `per_page` to a page, each page saying there are more.
        Flood { prefix: Vec<u8>, per_page: usize },
        /// Never answers.
        Silent,
        /// Serves what it holds for `pages` pages, then never answers.
        Stalls { pages: usize },
    }

    struct Net {
        ids: Vec<[u8; 32]>,
        held: Vec<Vec<Listing>>,
        behaviour: Vec<Behaviour>,
        served: Vec<usize>,
    }

    impl Net {
        fn new(nodes: usize, seed: u64) -> Self {
            Self {
                ids: (0..nodes).map(|n| id(seed * 1_000 + n as u64)).collect(),
                held: vec![Vec::new(); nodes],
                behaviour: vec![Behaviour::Honest; nodes],
                served: vec![0; nodes],
            }
        }

        /// Store `count` real listings, each on its 7 nearest nodes and, for
        /// every third, also on the nodes ranked 8 to 12. Their addresses.
        fn store(&mut self, count: u64) -> Vec<XorName> {
            let mut addresses = Vec::new();
            for n in 0..count {
                let address = id(1_000_000 + n);
                let ranked = nearest_by_distance(&address, &self.ids, 12);
                let holders = if n % 3 == 0 { 12 } else { NEAREST_NODES };
                for &node in ranked.iter().take(holders) {
                    self.held[node].push(real(address, n + 1));
                }
                addresses.push(address);
            }
            for held in &mut self.held {
                held.sort_by_key(Listing::key);
            }
            addresses
        }

        fn serve(&mut self, node: usize, from: ListingKey) -> Option<(Vec<Listing>, bool)> {
            self.served[node] += 1;
            match self.behaviour[node].clone() {
                Behaviour::Silent => None,
                Behaviour::Stalls { pages } if self.served[node] > pages => None,
                Behaviour::Honest | Behaviour::Stalls { .. } => {
                    let rest: Vec<&Listing> = self.held[node]
                        .iter()
                        .filter(|listing| listing.key() >= from)
                        .collect();
                    let page: Vec<Listing> = rest.iter().take(PAGE).map(|l| (*l).clone()).collect();
                    Some((page, rest.len() > PAGE))
                }
                Behaviour::Flood { prefix, per_page } => {
                    let hour = NOW - NOW % 3_600;
                    let mut counter: u64 = 0;
                    if from.time == hour && from.address.starts_with(&prefix) {
                        let mut tail = [0u8; 8];
                        tail.copy_from_slice(&from.address[24..]);
                        counter = u64::from_be_bytes(tail);
                    }
                    let page = (counter..counter + per_page as u64)
                        .map(|n| {
                            let mut address = [0u8; 32];
                            address[..prefix.len()].copy_from_slice(&prefix);
                            address[24..].copy_from_slice(&n.to_be_bytes());
                            fake(address)
                        })
                        .collect();
                    Some((page, true))
                }
            }
        }

        /// Walk every node from the start until nothing is left to ask,
        /// answering each round's requests in an order shuffled by `seed`.
        fn walk(&mut self, seed: u64) -> WalkResult<usize> {
            let mut walk = IndexWalk::new(
                self.ids
                    .iter()
                    .enumerate()
                    .map(|(node, id)| (node, *id, ListingKey::MIN)),
            );
            let mut round = 0;
            while !walk.idle() {
                let mut requests = walk.next_requests(64, NOW);
                requests.sort_by_key(|(node, _)| id(seed + round + *node as u64));
                for (node, from) in requests {
                    match self.serve(node, from) {
                        Some((page, more)) => walk.answer(&node, page, more),
                        None => walk.no_answer(&node),
                    }
                }
                round += 1;
            }
            walk.finish()
        }
    }

    fn support_of(result: &WalkResult<usize>, address: &XorName) -> usize {
        result
            .addresses
            .iter()
            .find(|found| found.address == *address)
            .map_or(0, |found| found.support)
    }

    #[test]
    fn nearest_by_distance_is_a_sort_by_xor_distance() {
        let ids: Vec<[u8; 32]> = (0..50).map(id).collect();
        for target in 0..20 {
            let address = id(10_000 + target);
            let mut sorted: Vec<usize> = (0..ids.len()).collect();
            sorted.sort_by_key(|&i| {
                let mut d = [0u8; 32];
                for k in 0..32 {
                    d[k] = address[k] ^ ids[i][k];
                }
                d
            });
            assert_eq!(nearest_by_distance(&address, &ids, 7), sorted[..7]);
            assert_eq!(nearest_by_distance(&address, &ids, 100), sorted);
        }
    }

    #[test]
    fn a_node_serving_endless_fakes_stops_after_eight_pages_and_nothing_fake_is_backed() {
        let mut net = Net::new(24, 1);
        let addresses = net.store(5_000);
        let prefix = net.ids[0][..8].to_vec();
        net.behaviour[0] = Behaviour::Flood {
            prefix: prefix.clone(),
            per_page: PAGE,
        };
        net.held[0].clear();
        let result = net.walk(7);

        let flooder = &result.nodes[0];
        assert_eq!(flooder.pages, 8);
        assert_eq!(flooder.listings, 8 * PAGE);
        assert_eq!(flooder.outcome, WalkOutcome::Budget);
        assert!(flooder.resume().is_some());
        for found in &result.addresses {
            if found.address.starts_with(&prefix) {
                assert_eq!(found.support, 1, "a fake is served by its maker only");
            }
        }
        for address in &addresses {
            assert!(support_of(&result, address) >= NEAREST_NODES - 1);
        }
        for node in &result.nodes[1..] {
            assert_eq!(node.outcome, WalkOutcome::Complete);
            assert_eq!(node.resume(), None);
        }
    }

    #[test]
    fn honest_walks_have_no_ceiling() {
        // About 5,800 listings a node, over 22 pages each: far past the free
        // eight, so every walk has to earn its way to the end.
        let mut net = Net::new(24, 2);
        let addresses = net.store(20_000);
        assert!(net
            .held
            .iter()
            .all(|held| held.len() > 3 * WALK_FREE_LISTINGS));
        for seed in 0..3 {
            net.served = vec![0; 24];
            let result = net.walk(seed * 100);
            for node in &result.nodes {
                assert_eq!(node.outcome, WalkOutcome::Complete, "{node:?}");
            }
            for address in &addresses {
                assert_eq!(support_of(&result, address), NEAREST_NODES);
            }
        }
    }

    /// A made-up listing near `prefix`, dated the hour of `time`.
    fn fake_at(prefix: &[u8], n: u64, time: u64) -> Listing {
        let mut address = [0u8; 32];
        address[..prefix.len()].copy_from_slice(prefix);
        address[24..].copy_from_slice(&n.to_be_bytes());
        Listing {
            first_seen: Some(time - time % 3_600),
            ..fake(address)
        }
    }

    #[test]
    fn relaying_real_listings_earns_a_bounded_allowance() {
        // Node 0 relays the real listings near it, half of them altered, and
        // that alone earns its walk to the end.
        let mut net = Net::new(24, 3);
        net.store(5_000);
        for (n, listing) in net.held[0].iter_mut().enumerate() {
            if n % 2 == 0 {
                listing.metadata.name = Some("altered".into());
            }
        }
        let result = net.walk(5);
        let relay = &result.nodes[0];
        assert_eq!(relay.outcome, WalkOutcome::Complete);
        assert!(PAGE * relay.pages <= WALK_FREE_LISTINGS + WALK_PER_BACKED * relay.backed);

        // Mixing 20,000 fakes in among them buys two fakes for each backed
        // copy, and no more.
        let mut net = Net::new(24, 3);
        net.store(5_000);
        let relayed = net.held[0].len();
        let prefix = net.ids[0][..8].to_vec();
        let times: Vec<u64> = net.held[0]
            .iter()
            .map(|listing| listing.key().time)
            .collect();
        for n in 0..20_000u64 {
            let time = times[usize::try_from(n).unwrap() % times.len()];
            net.held[0].push(fake_at(&prefix, n, time));
        }
        net.held[0].sort_by_key(Listing::key);
        let result = net.walk(5);
        let mixer = &result.nodes[0];
        assert_eq!(mixer.outcome, WalkOutcome::Budget);
        assert!(PAGE * mixer.pages <= WALK_FREE_LISTINGS + WALK_PER_BACKED * mixer.backed);
        assert!(mixer.backed <= relayed);
        assert!(mixer.listings < relayed + 20_000);
        for found in &result.addresses {
            if found.address.starts_with(&prefix) {
                assert_eq!(found.support, 1);
            }
        }
    }

    #[test]
    fn three_colluders_never_back_their_fakes() {
        // Three nodes whose ids share a long prefix, so they are all among
        // the nearest to the addresses they make up.
        let mut net = Net::new(24, 4);
        let prefix = vec![0x5a; 12];
        for node in 0..3 {
            net.ids[node][..12].copy_from_slice(&prefix);
        }
        let addresses = net.store(3_000);
        for node in 0..3 {
            net.held[node].clear();
            net.behaviour[node] = Behaviour::Flood {
                prefix: prefix.clone(),
                per_page: PAGE,
            };
        }
        let result = net.walk(9);
        for node in &result.nodes[..3] {
            assert_eq!(node.pages, 8);
            assert_eq!(node.outcome, WalkOutcome::Budget);
        }
        let fakes: Vec<&AddressWalk<usize>> = result
            .addresses
            .iter()
            .filter(|found| found.address.starts_with(&prefix))
            .collect();
        assert!(!fakes.is_empty());
        for found in fakes {
            assert!(found.support <= 3);
            assert!(found.support < QUORUM_THRESHOLD);
        }
        for address in &addresses {
            assert!(support_of(&result, address) >= QUORUM_THRESHOLD);
        }
    }

    #[test]
    fn a_short_page_saying_there_are_more_costs_a_full_one() {
        let mut net = Net::new(24, 5);
        net.store(1_000);
        let prefix = net.ids[0][..8].to_vec();
        net.behaviour[0] = Behaviour::Flood {
            prefix,
            per_page: 1,
        };
        net.held[0].clear();
        let result = net.walk(1);
        assert_eq!(result.nodes[0].pages, 8);
        assert_eq!(result.nodes[0].listings, 8);
        assert_eq!(net.served[0], 8);
    }

    #[test]
    fn copies_count_only_from_the_nearest_and_earn_only_within_twenty() {
        let mut net = Net::new(30, 6);
        let address = id(77);
        let ranked = nearest_by_distance(&address, &net.ids, 30);
        let listing = real(address, 1);
        // Its seven nearest hold it, and so do the nodes ranked 10 and 25.
        for &node in ranked.iter().take(NEAREST_NODES) {
            net.held[node].push(listing.clone());
        }
        net.held[ranked[9]].push(listing.clone());
        net.held[ranked[24]].push(listing.clone());
        let result = net.walk(3);
        let found = &result.addresses[0];
        assert_eq!(result.addresses.len(), 1);
        assert_eq!(found.support, NEAREST_NODES);
        assert_eq!(found.nearest, ranked[..NEAREST_NODES]);
        assert!(found
            .copies
            .iter()
            .all(|(node, _)| ranked[..NEAREST_NODES].contains(node)));
        assert_eq!(result.nodes[ranked[9]].backed, 1, "within twenty: earns");
        assert_eq!(result.nodes[ranked[24]].backed, 0, "beyond twenty: doesn't");
        assert_eq!(result.nodes[ranked[0]].backed, 1);
    }

    #[test]
    fn a_node_contradicting_itself_is_left_out_of_an_address() {
        let mut net = Net::new(24, 7);
        let address = id(88);
        let ranked = nearest_by_distance(&address, &net.ids, NEAREST_NODES);
        for &node in &ranked {
            net.held[node].push(real(address, 5));
        }
        // The nearest also sends a second copy, paid elsewhere.
        let mut other = real(address, 5);
        other.payment.log_index = Some(3);
        net.held[ranked[0]].push(other);
        net.held[ranked[0]].sort_by_key(Listing::key);
        let result = net.walk(0);
        let found = &result.addresses[0];
        assert_eq!(found.support, NEAREST_NODES - 1);
        assert!(found.copies.iter().all(|(node, _)| *node != ranked[0]));
    }

    #[test]
    fn nodes_that_stop_answering_are_asked_again_then_dropped_with_a_key_to_resume() {
        let mut net = Net::new(24, 8);
        net.store(20_000);
        net.behaviour[1] = Behaviour::Silent;
        net.behaviour[2] = Behaviour::Stalls { pages: 10 };
        let result = net.walk(4);

        let silent = &result.nodes[1];
        assert_eq!(silent.outcome, WalkOutcome::NoAnswer);
        assert_eq!(silent.pages, 0);
        assert_eq!(silent.resume(), None);
        assert_eq!(net.served[1], 2, "asked once, then once more");

        let stalled = &result.nodes[2];
        assert_eq!(stalled.outcome, WalkOutcome::NoAnswer);
        assert_eq!(stalled.pages, 10);
        assert_eq!(net.served[2], 12);
        let resume = stalled.resume().expect("a key to resume from");
        assert!(stalled.covered(&ListingKey::MIN));
        assert!(!stalled.covered(&resume));
    }

    #[test]
    fn a_stopped_walk_ignores_late_answers_and_says_where_to_resume() {
        let mut net = Net::new(24, 9);
        net.store(20_000);
        let mut walk = IndexWalk::new(
            net.ids
                .iter()
                .enumerate()
                .map(|(node, id)| (node, *id, ListingKey::MIN)),
        );
        for _ in 0..3 {
            for (node, from) in walk.next_requests(64, NOW) {
                let (page, more) = net.serve(node, from).expect("honest");
                walk.answer(&node, page, more);
            }
        }
        let late = walk.next_requests(64, NOW);
        assert!(!late.is_empty());
        walk.stop();
        for (node, from) in late {
            let (page, more) = net.serve(node, from).expect("honest");
            walk.answer(&node, page, more);
        }
        let result = walk.finish();
        for node in &result.nodes {
            assert_eq!(node.outcome, WalkOutcome::Deadline);
            assert_eq!(node.pages, 3);
            let resume = node.resume().expect("resume");
            assert!(resume > ListingKey::MIN);
            assert!(!node.covered(&resume));
        }
    }

    #[test]
    fn a_walk_resumed_part_way_covers_only_what_it_passed() {
        let mut net = Net::new(24, 10);
        let addresses = net.store(2_000);
        let middle = real(addresses[1_000], 1_001).key();
        let mut walk = IndexWalk::new(
            net.ids
                .iter()
                .enumerate()
                .map(|(node, id)| (node, *id, if node == 0 { middle } else { ListingKey::MIN })),
        );
        while !walk.idle() {
            for (node, from) in walk.next_requests(64, NOW) {
                let (page, more) = net.serve(node, from).expect("honest");
                walk.answer(&node, page, more);
            }
        }
        let result = walk.finish();
        let resumed = &result.nodes[0];
        assert_eq!(resumed.outcome, WalkOutcome::Complete);
        assert!(resumed.covered(&middle));
        assert!(!resumed.covered(&real(addresses[10], 11).key()));
    }

    #[test]
    fn a_smaller_quorum_is_only_for_small_test_networks() {
        let mut net = Net::new(3, 11);
        let address = id(5);
        for node in 0..3 {
            net.held[node].push(real(address, 1));
        }
        let mut walk = IndexWalk::new(
            net.ids
                .iter()
                .enumerate()
                .map(|(node, id)| (node, *id, ListingKey::MIN)),
        )
        .with_quorum(2);
        while !walk.idle() {
            for (node, from) in walk.next_requests(64, NOW) {
                let (page, more) = net.serve(node, from).expect("honest");
                walk.answer(&node, page, more);
            }
        }
        let result = walk.finish();
        assert_eq!(result.addresses[0].support, 3);
        assert_eq!(result.nodes[0].backed, 1);
        assert_eq!(result.nearest_to(&address).len(), 3);
    }
}
