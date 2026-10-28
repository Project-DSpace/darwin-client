//! Client operations for pointers (ADR-0016 in `ant-node`).
//!
//! A pointer is a mutable, owner-signed reference stored at
//! `BLAKE3::derive_key("autonomi.pointer.address.v1", owner_key)`. Public-key
//! addressed and self-verifying: the key is inside the record, so anything that
//! parses is checkable on the spot, with no fetch.
//!
//! # What the client owns
//!
//! - **The counter.** Creation is counter 0 and [`Client::pointer_update`]
//!   signs one past the counter the network serves, because the update has to
//!   beat it. A node takes any paid state that beats what it holds, so a
//!   counter may skip, a peer that missed updates takes the next one, and two
//!   states at one counter converge on the smaller target until a later
//!   counter replaces both.
//! - **Paying at the state, not the address.** The quote names `state_id`, while
//!   the close group that issues it is the one around the address. Paying at the
//!   address would buy every future update at once.
//! - **Following targets.** A node never interprets a pointer's target — it
//!   stores 33 opaque bytes. Chain resolution, its depth limit and its cycle
//!   detection are entirely here: see [`Client::pointer_resolve`].
//! - **Deciding between final states.** A state at the final counter is
//!   replaced by nothing, which is what lets an owner hand a pointer over for
//!   good ([`Client::pointer_transfer`], ADR-0018 in `ant-node`). Two different
//!   final states are the one fork left, made only by an owner racing them to
//!   different nodes, and each node keeps the one it took first. A read that
//!   meets a final state returns the one a majority of the close group holds,
//!   and reports a fork when none does; [`Client::pointer_finality`] asks the
//!   whole group, so a recipient can check a transfer before relying on it,
//!   and, before calling a pointer open, the bootstrap peers nearest it too.

use std::cmp::Reverse;
use std::collections::HashSet;
use std::future::Future;

use ant_protocol::chunk::{
    ChunkMessage, ChunkMessageBody, PointerGetRequest, PointerGetResponse, PointerPutRequest,
    PointerPutResponse,
};
use ant_protocol::pointer::{
    pointer_address, Pointer, PointerError, PointerTarget, PointerTargetKind, DATA_TYPE_POINTER,
    FINAL_COUNTER, POINTER_WIRE_LEN,
};
use ant_protocol::pqc::api::{MlDsaPublicKey, MlDsaSecretKey};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::XorName;
use bytes::Bytes;
use futures::future::{select, Either};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use web_time::Duration;

use crate::client_engine::{store_retry_delay, STORE_MAX_RETRIES};
use crate::data::client::batch::ChunkPaymentPlan;
use crate::data::client::chunk::STORE_RESPONSE_TIMEOUT;
#[cfg(feature = "native")]
use crate::data::client::occupied::{occupied_pointer_proof, plan_of_proof};
use crate::data::client::Client;
use crate::data::error::{Error, Result};
use crate::data::network::send_and_await_chunk_response;
use crate::runtime::sleep;

/// How many of `peers` must answer a read.
///
/// `peers` is the width of the set asked. For a close group it is the width
/// from [`quorum_width`]: the configured close group, or more peers than that
/// if a lookup returned more, never fewer; for the bootstrap peers a read also
/// asks, it is how many of them were asked. It is not a fixed constant,
/// because the close-group width is configurable, and a fixed four against a
/// width of twenty would let a write land on four peers and a *disjoint* four
/// answer the read. Quorums only intersect if both are taken from the same
/// set.
///
/// It is also the bare majority of the group, which is what decides between
/// two final states: at most one can be held by a majority.
fn read_quorum(peers: usize) -> usize {
    (peers / 2) + 1
}

/// How many of `peers` a write must reach.
///
/// One wider than a bare majority, which is what a chunk needs. A chunk is
/// self-proving — one copy is *the* chunk for that address — but a pointer read
/// has to decide which of several signed states is current, and a state that
/// only one peer reports is a state one peer decided. So a read requires two
/// peers to report what it returns ([`corroboration`]), and the write is one
/// wider so that two of them always answer: with `|W| + |R| >= K + 2` the two
/// sets overlap in at least two peers.
fn write_quorum(peers: usize) -> usize {
    (read_quorum(peers) + 1).min(peers)
}

/// How many of a pointer's close group must take a write, counted over the
/// configured close group (`close_group_size`): its write quorum, 5 of 7.
/// A state is quoted by too few to take it when fewer quote it, and nothing
/// is paid then ([`Client::get_store_quote_plan_split`]).
pub(crate) fn pointer_write_quorum(close_group_size: usize) -> usize {
    write_quorum(quorum_width(0, close_group_size))
}

/// How many peers must report a state before a read will return it.
///
/// Two, so that no single peer decides what a pointer says. A peer that is in
/// the close group and willing to serve what the owner never paid to store
/// could otherwise answer first with an owner-signed state no honest node
/// holds, and every reader would take it: the record verifies, it belongs at
/// the address, and it wins the merge. What it cannot do is make a second peer
/// agree.
///
/// A group of one can only ever be corroborated by itself.
fn corroboration(peers: usize) -> usize {
    peers.min(2)
}

/// How many members the quorums of an operation on `found` peers are counted
/// over: the configured close group, however few a lookup returned.
///
/// A lookup can come back short, while a node's view is thin or the network
/// churns. Counting quorums over what it returned would shrink them with it:
/// one returned peer would make a write of one copy complete, and a read that
/// one peer answers would need no second peer to agree. Counted over the whole
/// group, a short lookup is a shortfall instead.
fn quorum_width(found: usize, close_group_size: usize) -> usize {
    found.max(close_group_size)
}

/// The outcome of asking a set of peers: a close group, or the bootstrap peers.
#[derive(Default)]
struct Answered {
    /// How many peers gave a usable answer.
    count: usize,
    /// The last failure that was not a refusal, kept to explain a total
    /// failure.
    last_error: Option<Error>,
    /// The first failure that was a refusal rather than a missing answer: a
    /// peer that answered and said no. Asking again would get the same.
    refusal: Option<Error>,
    /// How many peers refused.
    refusals: usize,
    /// How many of the peers that failed were busy: held off for having
    /// declined a browser session while busy
    /// ([`crate::data::network::Network::refused_peers`]).
    busy: usize,
}

impl Answered {
    /// What to report when too few answered: a refusal if any peer gave one,
    /// since it says why, else the last failure.
    fn failure(self) -> Option<Error> {
        self.refusal.or(self.last_error)
    }

    /// Keep a peer's failure. A refusal is counted, and the first one is kept
    /// as the refusal; a failure worth retrying, and every refusal after the
    /// first, is kept as the latest failure.
    fn fail(&mut self, e: Error) {
        if worth_retrying(&e) {
            self.last_error = Some(e);
            return;
        }
        self.refusals += 1;
        if self.refusal.is_none() {
            self.refusal = Some(e);
        } else {
            self.last_error = Some(e);
        }
    }
}

/// Ask a whole close group at once and stop as soon as there is an answer.
///
/// The shape of a pointer write, which a read of one set of peers follows
/// ([`read_pointer_from`]): every peer is asked concurrently and each answer is
/// handed to `keep`, which says whether what it has is settled. It ends at the
/// first answer that is both settled and the `wanted`-th, or when the group is
/// exhausted. Stopping early is what keeps one unreachable peer from holding an
/// operation open for its whole timeout after the answer is already decided;
/// the requests still in flight are dropped, which cancels them.
async fn ask_the_group<T>(
    mut in_flight: FuturesUnordered<impl Future<Output = Result<T>>>,
    wanted: usize,
    mut keep: impl FnMut(T) -> bool,
) -> Answered {
    let mut answered = Answered::default();
    while let Some(result) = in_flight.next().await {
        match result {
            Ok(answer) => {
                answered.count += 1;
                let settled = keep(answer);
                if settled && answered.count >= wanted {
                    break;
                }
            }
            Err(e) => answered.fail(e),
        }
    }
    answered
}

/// What the peers answering a read have said.
///
/// A tally of every state offered, not a running winner. Keeping only the best
/// state and its count would let one peer erase the agreement behind another:
/// a single peer naming a higher state — which it cannot make anyone else
/// confirm — would discard the count behind the state the rest of the group
/// holds, and a healthy pointer would read back as uncorroborated. That is not
/// only an attack; it is what an ordinary read during an update looks like.
///
/// At most one entry per peer, so this is never longer than the set asked.
#[derive(Default)]
struct Replies {
    /// Each distinct state offered, and how many peers offered it.
    seen: Vec<(Pointer, usize)>,
}

impl Replies {
    /// Record one peer's answer. `None` is an answer that names no state.
    fn add(&mut self, reply: Option<Pointer>) {
        let Some(reply) = reply else { return };
        for (held, count) in &mut self.seen {
            if held.state_id() == reply.state_id() {
                *count += 1;
                return;
            }
        }
        self.seen.push((reply, 1));
    }

    /// The best state that at least `needed` peers named.
    ///
    /// Best by the merge rule, among the corroborated only: a stale state the
    /// group agrees on beats a newer one only one peer has heard of, because
    /// the second is one peer's word and the first is the network's.
    fn corroborated(&self, needed: usize) -> Option<&Pointer> {
        self.seen
            .iter()
            .filter(|(_, count)| *count >= needed)
            .map(|(record, _)| record)
            .reduce(|best, next| if next.replaces(best) { next } else { best })
    }

    /// Whether any peer named a state at all.
    fn any(&self) -> bool {
        !self.seen.is_empty()
    }

    /// How many peers named `record`'s state.
    fn holding(&self, record: &Pointer) -> usize {
        self.seen
            .iter()
            .find(|(held, _)| held.state_id() == record.state_id())
            .map_or(0, |(_, count)| *count)
    }

    /// The distinct final states named, with how many peers named each.
    fn finals(&self) -> impl Iterator<Item = &(Pointer, usize)> {
        self.seen.iter().filter(|(record, _)| record.is_terminal())
    }

    /// The final state at least `majority` peers named. At most one can be,
    /// so long as `majority` is a majority of the group.
    fn final_majority(&self, majority: usize) -> Option<&Pointer> {
        self.finals()
            .find(|(_, count)| *count >= majority)
            .map(|(record, _)| record)
    }

    /// What the tally says the pointer holds.
    ///
    /// Below the final counter, the best corroborated state. Once a final state
    /// has been named the merge rule no longer answers on its own: two
    /// different final states are unordered, and each node keeps whichever it
    /// took first. So the one a majority of the group holds is the answer, as
    /// it is the one most nodes accepted first. Without a majority, two final
    /// states are a fork with no answer, and one final state is taken as any
    /// state is — once corroborated — since nothing contests it.
    fn chosen(&self, needed: usize, majority: usize) -> Chosen<'_> {
        if let Some(held) = self.final_majority(majority) {
            return Chosen::State(Some(held));
        }
        if self.finals().nth(1).is_some() {
            return Chosen::Forked;
        }
        Chosen::State(self.corroborated(needed))
    }

    /// Whether what has been heard settles the read.
    ///
    /// Answers alone settle a read that found nothing. A state is settled only
    /// once enough peers have named it: until then the read keeps asking,
    /// because the peers that would confirm it may simply not have answered yet.
    ///
    /// Nor is it settled while a state that would replace it has been named
    /// by too few. The write and read quorums overlap in two peers, not two
    /// honest ones: after a write that reached a bare write quorum, the peers
    /// it missed hold the older state, and one more peer replaying that state
    /// corroborates it before a second holder of the newer state has
    /// answered. So the read waits for the rest of the group before letting
    /// the older state stand. The newer state still has to be corroborated to
    /// be returned, so no single peer decides the answer; one that names a
    /// state nobody else holds only makes the read ask everyone.
    ///
    /// A final state changes what settles a read. Nothing replaces it, but a
    /// different final state need not replace it to win: the one most of the
    /// group holds does. So once any final state has been named, the read is
    /// settled only by a final state a `majority` of the group has named, and
    /// otherwise asks everyone, so a fork is seen rather than guessed past.
    fn settled(&self, needed: usize, majority: usize) -> bool {
        if self.finals().next().is_some() {
            return self.final_majority(majority).is_some();
        }
        match self.corroborated(needed) {
            None => !self.any(),
            Some(best) => !self
                .seen
                .iter()
                .any(|(record, count)| *count < needed && record.replaces(best)),
        }
    }
}

/// What a read's tally settles on (see [`Replies::chosen`]).
#[derive(Debug)]
enum Chosen<'a> {
    /// This state, or none at all.
    State(Option<&'a Pointer>),
    /// Two or more different final states, none held by a majority.
    Forked,
}

/// A final state, as [`Client::pointer_finality`] reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalState {
    /// The state's identifier.
    pub state_id: XorName,
    /// The target's raw kind tag.
    pub kind_tag: u8,
    /// The target's address.
    pub target: XorName,
    /// How many peers of the close group hold it.
    pub holders: usize,
}

impl FinalState {
    fn of(record: &Pointer, holders: usize) -> Self {
        let target = record.target();
        Self {
            state_id: record.state_id(),
            kind_tag: target.kind_tag(),
            target: target.address,
            holders,
        }
    }

    /// The pointer this state hands the address over to, if it is a transfer
    /// rather than a freeze.
    #[must_use]
    pub fn transferred_to(&self) -> Option<XorName> {
        match PointerTargetKind::from_tag(self.kind_tag) {
            Some(PointerTargetKind::Pointer) => Some(self.target),
            _ => None,
        }
    }
}

/// Where a pointer stands with respect to finality, as the whole close group
/// reports it, and, while it reports the pointer open, as a read of the close
/// group and the bootstrap peers nearest the pointer finds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FinalityStatus {
    /// No peer of the close group that answered holds a final state, and a
    /// read of the close group and the bootstrap peers nearest the pointer
    /// returns none: the owner can still move the pointer. A peer that did
    /// not answer could hold one, so this rules a final state out only when
    /// every peer of the group answered ([`PointerFinality::answered`]
    /// equals [`PointerFinality::group`]). `counter` is the counter of the
    /// state that read returns, or `None` when neither the close group nor
    /// the bootstrap peers hold one, which the read reports only once every
    /// bootstrap peer asked has answered or failed.
    Open {
        /// The counter of the state a read would return.
        counter: Option<u64>,
    },
    /// One final state, and no other, but a majority of the group does not
    /// hold it yet: a transfer still spreading, or a write that fell short.
    /// Also a final state the close group doesn't hold but the bootstrap
    /// peers do, which a read returns ([`PointerFinality::seeds`]).
    Settling(FinalState),
    /// One final state, held by a majority of the group, and no other: every
    /// peer of the group answered and none holds a rival. Nothing can move
    /// the pointer off it.
    Final(FinalState),
    /// One final state, held by a majority of the group, and no other among
    /// the peers that answered, but not every peer of the group answered,
    /// or a peer of the group was held off as busy and so left out of the
    /// lookup, a farther peer answering in its place. A rival held by a peer
    /// that was not asked would not show, so this is not yet
    /// [`Self::Final`]; ask again once the whole group can answer.
    Unconfirmed(FinalState),
    /// The owner signed two or more different final states. `majority` is
    /// the one a majority holds, which reads return; with none, reads fail.
    Forked {
        /// Every final state seen, most-held first.
        states: Vec<FinalState>,
        /// The state a majority of the group holds, if any.
        majority: Option<FinalState>,
    },
}

/// The answer to [`Client::pointer_finality`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerFinality {
    /// The pointer asked about.
    pub address: XorName,
    /// How many peers the group has: the configured close group, or more if
    /// a lookup returned more.
    pub group: usize,
    /// How many of them answered.
    pub answered: usize,
    /// What they said.
    pub status: FinalityStatus,
    /// What the bootstrap peers nearest the pointer said, when the close
    /// group showed the pointer open and they were asked too; `None` when
    /// the close group holds a final state, or the client knows no
    /// bootstrap peer by peer ID.
    #[serde(default)]
    pub seeds: Option<SeedsView>,
}

/// What the bootstrap peers nearest a pointer hold, as
/// [`Client::pointer_finality`] reports it beside the close group's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedsView {
    /// How many bootstrap peers were asked: those nearest the pointer, nine
    /// at most, of the ones the client knows by peer ID.
    pub asked: usize,
    /// How many of them answered before the read settled.
    pub answered: usize,
    /// The state their answers settle on: the best state at least two of
    /// them name (the one peer, of one), or the final state a majority of
    /// them holds. `None` when no state is named by enough of them, or they
    /// name two final states and no majority holds either.
    pub state: Option<SeedState>,
}

/// A state the bootstrap peers hold ([`SeedsView::state`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedState {
    /// The state's identifier.
    pub state_id: XorName,
    /// Its counter: [`FINAL_COUNTER`] for a final state.
    pub counter: u64,
    /// The target's raw kind tag.
    pub kind_tag: u8,
    /// The target's address.
    pub target: XorName,
    /// How many of the bootstrap peers that answered name it.
    pub holders: usize,
}

impl SeedState {
    fn of(record: &Pointer, holders: usize) -> Self {
        let target = record.target();
        Self {
            state_id: record.state_id(),
            counter: record.counter(),
            kind_tag: target.kind_tag(),
            target: target.address,
            holders,
        }
    }

    /// Whether this is a final state.
    #[must_use]
    pub fn is_final(&self) -> bool {
        self.counter == FINAL_COUNTER
    }

    /// The pointer a final state hands the address over to, if it is a
    /// transfer rather than a freeze.
    #[must_use]
    pub fn transferred_to(&self) -> Option<XorName> {
        match PointerTargetKind::from_tag(self.kind_tag) {
            Some(PointerTargetKind::Pointer) if self.is_final() => Some(self.target),
            _ => None,
        }
    }
}

impl PointerFinality {
    /// Whether the pointer is final beyond dispute: one final state, held by a
    /// majority of the group, with no rival seen.
    #[must_use]
    pub fn is_final(&self) -> bool {
        matches!(self.status, FinalityStatus::Final(_))
    }

    /// The pointer this one was handed over to, once that is beyond dispute.
    #[must_use]
    pub fn transferred_to(&self) -> Option<XorName> {
        match &self.status {
            FinalityStatus::Final(state) => state.transferred_to(),
            _ => None,
        }
    }
}

/// What [`Client::pointer_transfer`] stored, and what the close group said
/// about it afterwards.
#[derive(Debug)]
pub struct PointerTransfer {
    /// The pointer handed over.
    pub address: XorName,
    /// The final state stored.
    pub state_id: XorName,
    /// The whole close group's view once the write landed. An error here does
    /// not undo the transfer, which is stored and final; only the check
    /// failed. Ask again with [`Client::pointer_finality`].
    pub finality: Result<PointerFinality>,
}

/// Whose pointer decides what an address resolves to, after following every
/// transfer (see [`Client::pointer_controller`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerController {
    /// The pointer whose owner decides: the address asked about, or the last
    /// pointer it was handed over to.
    pub pointer: XorName,
    /// Every pointer the address was handed over to, in order.
    pub transfers: Vec<XorName>,
    /// Whether that pointer is final without being handed over: nobody can
    /// move it any more.
    pub frozen: bool,
}

/// A final state's description for an error: its identifier and target.
fn describe_final(record: &Pointer) -> String {
    let target = record.target();
    let kind = match target.kind() {
        Some(PointerTargetKind::Pointer) => "pointer",
        Some(PointerTargetKind::Chunk) => "chunk",
        None => "unknown kind",
    };
    format!(
        "final state {} targeting {kind} {}",
        hex::encode(record.state_id()),
        hex::encode(target.address)
    )
}

/// The error for a transfer the network refused because the pointer is
/// already final on another state, if that is what `finality` shows.
fn rival_final(finality: &PointerFinality, ours: &Pointer) -> Option<Error> {
    let ours = ours.state_id();
    let address = hex::encode(finality.address);
    match &finality.status {
        FinalityStatus::Open { .. } => None,
        FinalityStatus::Settling(state)
        | FinalityStatus::Final(state)
        | FinalityStatus::Unconfirmed(state) => (state.state_id != ours).then(|| {
            Error::PointerFinal(format!(
                "pointer {address} is already final on state {} held by {} of {} peers",
                hex::encode(state.state_id),
                state.holders,
                finality.group
            ))
        }),
        FinalityStatus::Forked { states, .. } => Some(Error::PointerForked(format!(
            "pointer {address} holds {} different final states",
            states.len()
        ))),
    }
}

/// The error for an update to a pointer on which any peer holds a final
/// state, if that is what `finality` shows.
///
/// A final state even one peer holds was signed by the owner, and no node
/// holding it will take an update: a transfer or freeze that fell short.
fn final_already(finality: &PointerFinality) -> Option<Error> {
    let address = hex::encode(finality.address);
    match &finality.status {
        FinalityStatus::Open { .. } => None,
        FinalityStatus::Settling(state)
        | FinalityStatus::Final(state)
        | FinalityStatus::Unconfirmed(state) => Some(Error::PointerFinal(format!(
            "pointer {address} has final state {} on {} of {} peers; an update cannot \
             replace it",
            hex::encode(state.state_id),
            state.holders,
            finality.group
        ))),
        FinalityStatus::Forked { states, .. } => Some(Error::PointerForked(format!(
            "pointer {address} holds {} different final states",
            states.len()
        ))),
    }
}

/// What a transfer whose write reported failure comes to, given the finality
/// check made after it.
///
/// A rival final state is the reason, and is named. The transfer's own state
/// held by a majority means the write landed although its acknowledgements
/// were lost: the transfer is stored and final, so it is reported as done, not
/// failed, and nobody pays for it twice. Anything else is the write's own
/// error.
fn after_failed_transfer(
    put: Error,
    finality: Result<PointerFinality>,
    record: &Pointer,
) -> Result<PointerFinality> {
    let Ok(finality) = finality else {
        return Err(put);
    };
    if let Some(refusal) = rival_final(&finality, record) {
        return Err(refusal);
    }
    let ours = record.state_id();
    match &finality.status {
        FinalityStatus::Final(state) | FinalityStatus::Unconfirmed(state)
            if state.state_id == ours =>
        {
            Ok(finality)
        }
        _ => Err(put),
    }
}

/// What a finality check makes of a tally over a group of `group` peers, of
/// which `answered` answered.
fn finality_status(replies: &Replies, group: usize, answered: usize) -> FinalityStatus {
    let majority = read_quorum(group);
    let mut finals: Vec<FinalState> = replies
        .finals()
        .map(|(record, count)| FinalState::of(record, *count))
        .collect();
    finals.sort_by_key(|state| Reverse(state.holders));
    let held_by_majority = finals
        .iter()
        .find(|state| state.holders >= majority)
        .cloned();
    match finals.as_slice() {
        [] => FinalityStatus::Open {
            counter: replies
                .corroborated(corroboration(group))
                .map(Pointer::counter),
        },
        [only] if only.holders >= majority && answered >= group => {
            FinalityStatus::Final(only.clone())
        }
        [only] if only.holders >= majority => FinalityStatus::Unconfirmed(only.clone()),
        [only] => FinalityStatus::Settling(only.clone()),
        _ => FinalityStatus::Forked {
            states: finals,
            majority: held_by_majority,
        },
    }
}

/// Ask every peer of the close group of `address` (`close_group`, its
/// lookup) for the pointer, each within its own deadline (`get`), and say
/// where it stands from their answers alone, with the tally they make.
///
/// This is the census [`Client::pointer_finality`] starts from, and the whole
/// of the check an update or a transfer makes before paying, which asks no
/// bootstrap peer. Unlike a read it does not stop once it has an answer, so a
/// second final state held by even one peer is seen. Its quorum is counted
/// over the configured close group ([`quorum_width`]). It also says which
/// peers it asked and which answered ([`Contacted`]), whether it gives an
/// answer or fails.
///
/// `held_off` lists the peers held off as busy when it began, which the
/// lookup left out. When one of them would rank among the close group beside
/// the peers asked ([`displaces_the_group`]), a member of the true group was
/// never asked and a rival final state it holds would not show, so a state
/// every peer asked holds is [`FinalityStatus::Unconfirmed`], not
/// [`FinalityStatus::Final`].
async fn close_group_census<L, G, GF>(
    address: &XorName,
    close_group: L,
    close_group_size: usize,
    get: G,
    held_off: &[PeerId],
) -> (Result<(PointerFinality, Replies)>, Contacted)
where
    L: Future<Output = Result<Vec<(PeerId, Vec<MultiAddr>)>>>,
    G: Fn(PeerId, Vec<MultiAddr>) -> GF,
    GF: Future<Output = Result<Option<Pointer>>>,
{
    let peers = match close_group.await {
        Ok(peers) => peers,
        Err(failure) => return (Err(failure), Contacted::default()),
    };
    let in_flight: FuturesUnordered<_> = peers
        .iter()
        .map(|(peer, addrs)| {
            let peer = *peer;
            let reply = get(peer, addrs.clone());
            async move { reply.await.map(|found| (peer, found)) }
        })
        .collect();
    let mut replies = Replies::default();
    let mut contacted = Contacted {
        asked: peers.iter().map(|(peer, _)| *peer).collect(),
        answered: HashSet::new(),
    };
    let answered = ask_the_group(in_flight, peers.len(), |(peer, found)| {
        contacted.answered.insert(peer);
        replies.add(found);
        false
    })
    .await;

    // Counted over the configured group, as every pointer quorum is: a
    // lookup that came back short is peers that did not answer, not a
    // smaller group.
    let width = quorum_width(peers.len(), close_group_size);
    let wanted = read_quorum(width);
    if answered.count < wanted {
        let count = answered.count;
        let failure = answered
            .failure()
            .filter(|_| count == 0)
            .unwrap_or_else(|| {
                Error::CloseGroupShortfall(format!(
                    "only {count} of the close group answered for pointer {}",
                    hex::encode(address)
                ))
            });
        return (Err(failure), contacted);
    }
    let status = match finality_status(&replies, width, answered.count) {
        FinalityStatus::Final(state)
            if displaces_the_group(address, close_group_size, &contacted.asked, held_off) =>
        {
            FinalityStatus::Unconfirmed(state)
        }
        status => status,
    };
    let finality = PointerFinality {
        address: *address,
        group: width,
        answered: answered.count,
        status,
        seeds: None,
    };
    (Ok((finality, replies)), contacted)
}

/// What a census of the close group that shows the pointer open (`census`,
/// whose tally is `replies`) comes to once `read`, a read of the close group
/// and the bootstrap peers nearest the pointer, has asked them as well:
///
/// - the read's error, as [`Client::pointer_get`] gives it;
/// - a final state the read returns: [`FinalityStatus::Settling`], held by
///   the peers of the close group that named it in the census (none, since
///   the census showed no final state), never open;
/// - another state: open, at the counter of the state the read returns;
/// - none: open with no state, which the read returns only once every
///   bootstrap peer asked has answered or failed.
fn with_the_read(
    census: PointerFinality,
    replies: &Replies,
    read: PointerRead,
) -> Result<PointerFinality> {
    let status = match read.found? {
        None => FinalityStatus::Open { counter: None },
        Some(state) if state.is_terminal() => {
            FinalityStatus::Settling(FinalState::of(&state, replies.holding(&state)))
        }
        Some(state) => FinalityStatus::Open {
            counter: Some(state.counter()),
        },
    };
    Ok(PointerFinality {
        status,
        seeds: read.seeds,
        ..census
    })
}

/// One round of [`Client::pointer_finality`] on a network given as
/// functions: the close group's census (`close_group` looks the group up,
/// `get` asks one peer), and, while it shows the pointer open, the read
/// [`Client::pointer_get`] makes, which also asks `bootstrap`
/// ([`with_the_read`]); with the peers the two asked ([`Contacted`]), which
/// [`past_refusals`] weighs before taking the answer. `busy` and `held_off`
/// are the read's ([`read_pointer_with_seeds`]).
async fn pointer_finality_from<L, LF, G, GF>(
    address: &XorName,
    close_group: L,
    close_group_size: usize,
    bootstrap: &[(PeerId, Vec<MultiAddr>)],
    get: G,
    busy: impl Fn(&PeerId) -> bool,
    held_off: &[PeerId],
) -> (Result<PointerFinality>, Contacted)
where
    L: Fn() -> LF,
    LF: Future<Output = Result<Vec<(PeerId, Vec<MultiAddr>)>>>,
    G: Fn(PeerId, Vec<MultiAddr>) -> GF,
    GF: Future<Output = Result<Option<Pointer>>>,
{
    let (census, contacted) =
        close_group_census(address, close_group(), close_group_size, &get, held_off).await;
    let (census, replies) = match census {
        Ok(census) => census,
        Err(failure) => return (Err(failure), contacted),
    };
    if !finality_is_open(&census) {
        return (Ok(census), contacted);
    }
    let mut read = read_pointer_with_seeds(
        address,
        close_group(),
        close_group_size,
        bootstrap,
        &get,
        busy,
        held_off,
    )
    .await;
    let contacted = contacted.join(std::mem::take(&mut read.contacted));
    (with_the_read(census, &replies, read), contacted)
}

/// The peers one round of a pointer read or census asked, and those of them
/// that answered, bootstrap peers included.
#[derive(Default)]
struct Contacted {
    asked: HashSet<PeerId>,
    answered: HashSet<PeerId>,
}

impl Contacted {
    /// Both rounds' peers, as one.
    fn join(mut self, other: Self) -> Self {
        self.asked.extend(other.asked);
        self.answered.extend(other.answered);
        self
    }
}

/// The error a pointer read gives when the peers that may hold the pointer
/// are held off for having declined a session while busy: the words a chunk
/// read uses.
fn pointer_holders_busy(address: &XorName) -> Error {
    Error::Network(format!(
        "the nodes that may hold pointer {} are busy; try again shortly",
        hex::encode(address)
    ))
}

/// How long to wait before reading `address` again, because peers held off
/// for having declined a session while busy may hold a state the round that
/// `contacted` its peers missed; `None` when its answer stands.
///
/// A held-off peer is left out of the lookup before it is asked, so the
/// round asks farther peers in its place, and their answers fill the quorum
/// counted over the close group. Ranked against the peers the round asked,
/// `refused_at_start` (held off when it began) and `refused_now` (held off
/// now, with the time until each is tried again) give the close group the
/// round should have asked: the `close_group_size` nearest the address. When
/// a held-off peer is among them and fewer than a read quorum of them
/// answered, the answer stands on peers outside the group: a write quorum of
/// the group can hold a newer state none of them was asked for. With a read
/// quorum of that group answering, two of any write quorum answered, as a
/// read with no peer held off needs ([`write_quorum`]), so the answer stands.
///
/// The wait lasts until the first such hold-off ends, and at least
/// [`CLOSE_GROUP_RETRY_DELAY`](crate::client_engine::read::CLOSE_GROUP_RETRY_DELAY)
/// when one ended during the round, as a chunk read waits.
fn held_off_wait(
    address: &XorName,
    close_group_size: usize,
    contacted: &Contacted,
    refused_at_start: &[(PeerId, Duration)],
    refused_now: &[(PeerId, Duration)],
) -> Option<Duration> {
    let held_off: HashSet<PeerId> = refused_at_start
        .iter()
        .chain(refused_now)
        .map(|(peer, _)| *peer)
        .filter(|peer| !contacted.answered.contains(peer))
        .collect();
    if held_off.is_empty() {
        return None;
    }
    let mut group: Vec<PeerId> = contacted.asked.union(&held_off).copied().collect();
    group.sort_by_key(|peer| ant_protocol::transport::xor_distance(peer.as_bytes(), address));
    group.truncate(close_group_size);
    let answered = group
        .iter()
        .filter(|peer| contacted.answered.contains(*peer))
        .count();
    if answered >= read_quorum(close_group_size) {
        return None;
    }
    group
        .iter()
        .filter(|peer| held_off.contains(*peer))
        .map(|peer| {
            refused_now
                .iter()
                .find(|(refused, _)| refused == peer)
                .map_or(Duration::ZERO, |(_, remaining)| *remaining)
        })
        .min()
        .map(|remaining| remaining.max(crate::client_engine::read::CLOSE_GROUP_RETRY_DELAY))
}

/// Whether any of `held_off`, peers held off for having declined a session
/// while busy, would rank among the `close_group_size` nearest `address`
/// beside `group`, a lookup that left it out.
fn displaces_the_group(
    address: &XorName,
    close_group_size: usize,
    group: &HashSet<PeerId>,
    held_off: &[PeerId],
) -> bool {
    held_off.iter().any(|peer| {
        let distance = ant_protocol::transport::xor_distance(peer.as_bytes(), address);
        !group.contains(peer)
            && group
                .iter()
                .filter(|member| {
                    ant_protocol::transport::xor_distance(member.as_bytes(), address) < distance
                })
                .count()
                < close_group_size
    })
}

/// Run `round`, a pointer read or census, until no peer held off for having
/// declined a session while busy may change its answer ([`held_off_wait`]).
///
/// `refused` lists the peers held off now, each with the time until it is
/// tried again ([`crate::data::network::Network::refused_peers`]), and `open`
/// says whether an answer is one such a peer could change: absence, or a
/// state a newer one replaces. An error those peers can explain is weighed
/// the same way ([`held_off_may_explain`]): too few of the group answering
/// or naming one state, a lookup that found nobody, the group's members
/// declining as busy during the round, or two final states no majority of
/// those asked holds. A final state, or any other error, is returned as it
/// is. Each wait lasts until the first hold-off that may hide a holder
/// ends, up to
/// [`MAX_REFUSAL_WAITS`](crate::client_engine::read::MAX_REFUSAL_WAITS)
/// times, as a chunk read waits, and then the read fails with
/// [`pointer_holders_busy`] rather than give an answer those peers may
/// replace. Each round looks the close group up again. A native client
/// holds no peer off, so its round runs once.
async fn past_refusals<T, R, RF>(
    address: &XorName,
    close_group_size: usize,
    refused: impl Fn() -> Vec<(PeerId, Duration)>,
    open: impl Fn(&T) -> bool,
    round: R,
) -> Result<T>
where
    R: Fn() -> RF,
    RF: Future<Output = (Result<T>, Contacted)>,
{
    let mut waits = 0;
    loop {
        let refused_at_start = refused();
        let (found, contacted) = round().await;
        let weighed = match &found {
            Ok(answer) => open(answer),
            Err(failure) => held_off_may_explain(address, failure),
        };
        let wait = if weighed {
            held_off_wait(
                address,
                close_group_size,
                &contacted,
                &refused_at_start,
                &refused(),
            )
        } else {
            None
        };
        match wait {
            None => return found,
            Some(_) if waits == crate::client_engine::read::MAX_REFUSAL_WAITS => {
                return Err(pointer_holders_busy(address));
            }
            Some(remaining) => {
                waits += 1;
                debug!(
                    "pointer {}: peers held off as busy may hold a newer state; reading again \
                     in {remaining:?} ({waits}/{})",
                    hex::encode(address),
                    crate::client_engine::read::MAX_REFUSAL_WAITS
                );
                sleep(remaining).await;
            }
        }
    }
}

/// Whether a pointer read or census that failed with `failure` may have
/// failed only because peers held off as busy were left out of its lookup or
/// declined it during the round ([`past_refusals`]): a shortfall (too few of
/// the group answered, too few named one state, or the lookup found nobody),
/// the group's peers busy ([`pointer_holders_busy`]), or two final states no
/// majority of those asked holds, which the group's other members may
/// settle. Any other failure is the read's answer.
fn held_off_may_explain(address: &XorName, failure: &Error) -> bool {
    match failure {
        Error::CloseGroupShortfall(_) | Error::PointerForked(_) => true,
        Error::Network(message) => {
            matches!(pointer_holders_busy(address), Error::Network(busy) if *message == busy)
        }
        _ => false,
    }
}

/// Whether a read's answer is one a peer held off as busy could change
/// ([`past_refusals`]): absence, or a state a newer one replaces. No state
/// replaces a final one.
fn read_is_open(found: &Option<Pointer>) -> bool {
    !found.as_ref().is_some_and(Pointer::is_terminal)
}

/// Whether a finality check's answer is one a peer held off as busy could
/// change ([`past_refusals`]): the pointer open, with a state or none.
fn finality_is_open(finality: &PointerFinality) -> bool {
    matches!(finality.status, FinalityStatus::Open { .. })
}

/// What one peer's acknowledgement of a pointer PUT says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PutAck {
    /// It holds the state that was sent.
    Stored,
    /// It holds a state it says beats the one sent. That is one peer's word,
    /// not a verified record, so a write stops for it only once a read
    /// confirms the pointer has moved on.
    Stale,
}

/// Whether one round of a pointer write stored it, from what came back.
///
/// `stored` peers hold the record, `wanted` is the write quorum, and `moved`
/// says a read confirmed the network holds a state that replaces it.
///
/// A refusal ends the write only when no peer stored the record and a second
/// peer refused as well. Once any peer has taken the same proof, one peer
/// refusing it is that peer's problem; and while the rest of the group is
/// silent, one refusal is that peer's word alone. Either way the round is a
/// shortfall to retry with the proof already paid for, rather than a final
/// answer one peer gave that throws the payment away.
fn judge_write(
    address: &XorName,
    stored: usize,
    wanted: usize,
    moved: bool,
    answered: Answered,
) -> Result<()> {
    if stored >= wanted {
        return Ok(());
    }
    if moved {
        return Err(Error::InvalidData(format!(
            "the pointer {} moved while this update was in flight; the network now \
             holds a newer state",
            hex::encode(address)
        )));
    }
    if stored == 0 && answered.refusals >= corroboration(wanted) {
        if let Some(refusal) = answered.refusal {
            return Err(refusal);
        }
    }
    if answered.count > 0 || answered.refusals > 0 {
        return Err(Error::CloseGroupShortfall(format!(
            "pointer {} stored on {stored} of {wanted} close-group peers",
            hex::encode(address)
        )));
    }
    Err(answered
        .last_error
        .unwrap_or_else(|| Error::Protocol("no close-group peer accepted the pointer".to_string())))
}

/// Which peers a pointer read asked.
#[derive(Clone, Copy)]
enum Asked {
    /// The close group of the address.
    CloseGroup,
    /// The bootstrap peers nearest the address, of those the client knows by
    /// peer ID.
    Bootstrap,
}

impl Asked {
    /// The set, as in "only 3 of the close group answered".
    fn set(self) -> &'static str {
        match self {
            Self::CloseGroup => "the close group",
            Self::Bootstrap => "the bootstrap peers",
        }
    }

    /// One of its peers, as in "no close-group peer answered".
    fn member(self) -> &'static str {
        match self {
            Self::CloseGroup => "close-group peer",
            Self::Bootstrap => "bootstrap peer",
        }
    }
}

/// What one set of peers has answered a pointer read so far.
///
/// Every reply is verified independently, so a dishonest peer can only offer a
/// record that is genuinely signed and genuinely belongs here. What it must not
/// be able to do is decide the answer alone: any peer may legitimately hold a
/// stale record, so taking the first reply would let one pin a reader to it.
/// The read needs [`read_quorum`] of the set to answer and returns what the
/// answers settle on ([`Replies::chosen`]): the best state at least
/// [`corroboration`] of them name, or, once a final state is named, the final
/// state a majority of the set holds. Both are taken from the set's size.
struct ReadTally {
    /// How many peers the set has: for a close group, its width
    /// ([`quorum_width`]).
    peers: usize,
    answered: Answered,
    replies: Replies,
}

impl ReadTally {
    fn new(peers: usize) -> Self {
        Self {
            peers,
            answered: Answered::default(),
            replies: Replies::default(),
        }
    }

    /// One peer's answer. `None` names no state.
    fn answer(&mut self, found: Option<Pointer>) {
        self.answered.count += 1;
        self.replies.add(found);
    }

    /// One peer's failure. `busy` says the peer is held off for having
    /// declined a session while busy, which makes a shortfall it causes a
    /// busy network rather than too few holders.
    fn fail(&mut self, e: Error, busy: bool) {
        if busy {
            self.answered.busy += 1;
        }
        self.answered.fail(e);
    }

    /// Whether [`read_quorum`] of the set has answered.
    fn has_quorum(&self) -> bool {
        self.answered.count >= read_quorum(self.peers)
    }

    /// What the answers so far settle on ([`Replies::chosen`]).
    fn chosen(&self) -> Chosen<'_> {
        self.replies
            .chosen(corroboration(self.peers), read_quorum(self.peers))
    }

    /// Whether the read of this set alone would stop here: a quorum of it has
    /// answered and what they said is settled ([`Replies::settled`]). A state
    /// a newer one named by too few would replace, or a final state too few
    /// hold to be a majority, keeps the read asking the rest of the set.
    fn settled(&self) -> bool {
        self.has_quorum()
            && self
                .replies
                .settled(corroboration(self.peers), read_quorum(self.peers))
    }

    /// The state this set returns, once it has one: none while too few of it
    /// have answered, or while its answers name two final states and no
    /// majority holds either.
    fn state(&self) -> Option<&Pointer> {
        match self.chosen() {
            Chosen::State(state) => state.filter(|_| self.has_quorum()),
            Chosen::Forked => None,
        }
    }

    /// Whether any answer names a state that replaces `held`.
    fn names_newer_than(&self, held: &Pointer) -> bool {
        self.replies
            .seen
            .iter()
            .any(|(state, _)| state.replaces(held))
    }

    /// The set's outcome, and the state its answers settle on even when too
    /// few of the set answered for that to be the outcome: none when they name
    /// a fork.
    fn finish(self, address: &XorName, asked: Asked) -> SetRead {
        let seen = match self.chosen() {
            Chosen::State(state) => state.cloned(),
            Chosen::Forked => None,
        };
        SetRead {
            outcome: self.outcome(address, asked),
            seen,
        }
    }

    /// What this set, the bootstrap peers asked, holds, for
    /// [`PointerFinality::seeds`]: the state its answers settle on, and how
    /// many of them named it.
    fn seeds_view(&self) -> SeedsView {
        let state = match self.chosen() {
            Chosen::State(Some(record)) => {
                Some(SeedState::of(record, self.replies.holding(record)))
            }
            Chosen::State(None) | Chosen::Forked => None,
        };
        SeedsView {
            asked: self.peers,
            answered: self.answered.count,
            state,
        }
    }

    fn outcome(self, address: &XorName, asked: Asked) -> Result<Option<Pointer>> {
        let needed = corroboration(self.peers);
        let majority = read_quorum(self.peers);
        // Too few answered and some of those that did not were busy: asked
        // again once their hold-off ends they may answer, so say so, in the
        // words a chunk read uses, rather than report too few holders. A
        // refusal still comes first when no peer answered, since it says why.
        let busy = !self.has_quorum()
            && self.answered.busy > 0
            && (self.answered.count > 0 || self.answered.refusal.is_none());
        if busy {
            return Err(pointer_holders_busy(address));
        }
        if self.answered.count == 0 {
            return Err(self.answered.failure().unwrap_or_else(|| {
                Error::Protocol(format!("no {} answered for the pointer", asked.member()))
            }));
        }
        // A single answer is not a network verdict: one reachable peer holding
        // a stale record, before replication has reached it, looks exactly like
        // the whole group agreeing. Say so rather than presenting it as the
        // value.
        if !self.has_quorum() {
            return Err(Error::CloseGroupShortfall(format!(
                "only {} of {} answered for pointer {}",
                self.answered.count,
                asked.set(),
                hex::encode(address)
            )));
        }
        // The owner signed two final states and no majority of the set holds
        // either: there is nothing to return that the rest of the network
        // would agree with, and asking again sees the same split.
        let corroborated = match self.replies.chosen(needed, majority) {
            Chosen::State(state) => state.cloned(),
            Chosen::Forked => {
                return Err(Error::PointerForked(format!(
                    "pointer {} holds {} different final states and none is held by \
                     {majority} of the {} {}s",
                    hex::encode(address),
                    self.replies.finals().count(),
                    self.peers,
                    asked.member()
                )));
            }
        };
        // States were offered, but none by enough peers to call it the
        // network's answer. Either the write is still settling, or what was
        // offered is a state no honest node holds. Neither is a value to hand
        // back as current.
        if corroborated.is_none() && self.replies.any() {
            return Err(Error::CloseGroupShortfall(format!(
                "no state for pointer {} was named by {needed} of the {} peers that answered",
                hex::encode(address),
                self.answered.count
            )));
        }
        Ok(corroborated)
    }
}

/// What a read of one set of peers found.
struct SetRead {
    /// The set's answer, under its own quorum and corroboration.
    outcome: Result<Option<Pointer>>,
    /// The best state the set's answers corroborate, which a set too few of
    /// whose peers answered still reports.
    seen: Option<Pointer>,
}

/// Read the pointer at `address` from one set of peers, all asked at once:
/// `in_flight` holds their verified replies, each with the peer that gave it,
/// `peers` is how many there are, and `busy` says whether a peer that failed
/// is held off for having declined a session while busy. Each peer that
/// answers is added to `answered`.
/// It stops as soon as the set's answer is settled, and the requests still in
/// flight are dropped, so one slow peer cannot stall the read behind the store
/// timeout; with `ask_all`, only once every peer has answered or failed.
async fn read_pointer_from(
    mut in_flight: FuturesUnordered<impl Future<Output = (PeerId, Result<Option<Pointer>>)>>,
    peers: usize,
    address: &XorName,
    asked: Asked,
    busy: impl Fn(&PeerId) -> bool,
    ask_all: bool,
    answered: &mut HashSet<PeerId>,
) -> SetRead {
    let mut tally = ReadTally::new(peers);
    while let Some((peer, result)) = in_flight.next().await {
        match result {
            Ok(found) => {
                answered.insert(peer);
                tally.answer(found);
                if tally.settled() && !ask_all {
                    break;
                }
            }
            Err(e) => tally.fail(e, busy(&peer)),
        }
    }
    tally.finish(address, asked)
}

/// [`read_pointer_with_seeds`]'s answer alone, as the tests read it.
#[cfg(test)]
async fn read_pointer<L, G, GF>(
    address: &XorName,
    close_group: L,
    close_group_size: usize,
    bootstrap: &[(PeerId, Vec<MultiAddr>)],
    get: G,
    busy: impl Fn(&PeerId) -> bool,
) -> Result<Option<Pointer>>
where
    L: Future<Output = Result<Vec<(PeerId, Vec<MultiAddr>)>>>,
    G: Fn(PeerId, Vec<MultiAddr>) -> GF,
    GF: Future<Output = Result<Option<Pointer>>>,
{
    read_pointer_with_seeds(
        address,
        close_group,
        close_group_size,
        bootstrap,
        get,
        busy,
        &[],
    )
    .await
    .found
}

/// The bootstrap peers a pointer read asks beside the close group: of `seeds`,
/// the nine nearest `address` of those the client knows by peer ID
/// ([`crate::data::network::bootstrap_read_peers`]), those the close group's
/// lookup, `group`, leaves among the nine nearest, and never fewer than
/// [`crate::data::network::MIN_POINTER_READ_SEEDS`] (the nearest of the rest
/// make up the number), or every one when the lookup failed or found nobody
/// ([`crate::data::network::seeds_for_read`]).
fn seeds_beside(
    group: Option<&[(PeerId, Vec<MultiAddr>)]>,
    seeds: Vec<(PeerId, Vec<MultiAddr>)>,
    address: &XorName,
) -> Vec<(PeerId, Vec<MultiAddr>)> {
    match group {
        Some(group) => crate::data::network::seeds_for_read(
            &seeds,
            group.iter().map(|(peer, _)| *peer.as_bytes()),
            address,
            |(peer, _)| *peer.as_bytes(),
            crate::data::network::MIN_POINTER_READ_SEEDS,
        ),
        None => seeds,
    }
}

/// A pointer read, and what the bootstrap peers asked beside the close group
/// said.
struct PointerRead {
    /// The read's answer.
    found: Result<Option<Pointer>>,
    /// The bootstrap peers' part, or `None` when there were none to ask.
    seeds: Option<SeedsView>,
    /// The peers the read asked, of both sets, and those that answered.
    contacted: Contacted,
}

/// Read the pointer at `address` from its close group and from `bootstrap`,
/// the bootstrap peers nearest it of those the client knows by peer ID (nine
/// at most: [`crate::data::network::bootstrap_read_peers`]), at once, and
/// combine the two reads by [`newest_pointer`]. `close_group` looks the close
/// group up, and `get` asks one peer. Without bootstrap peers this is a read of
/// the close group alone.
///
/// The bootstrap peers are asked from the start and the close group as soon as
/// it is known. A peer in both sets is asked once, and its answer counts in
/// each. Each set keeps its own [`read_quorum`] and [`corroboration`], and the
/// close group stops as a read of it alone does ([`ReadTally::settled`]). The
/// bootstrap peers stop once a quorum of them has answered and their answers
/// give a state ([`ReadTally::state`]); once the close group has returned a
/// state, as soon as a quorum of them has answered and none names a newer one;
/// and otherwise only once every one of them has answered or failed, so that a
/// state only a few of them hold is still found when the close group has none.
/// The read takes as long as the slower set.
///
/// The close group's quorums are counted over its width ([`quorum_width`]):
/// `close_group_size`, or more peers if the lookup returned more, so a lookup
/// that comes back short is a shortfall rather than a smaller group. The
/// bootstrap peers' are counted over the peers asked.
///
/// `busy` says whether a peer that failed is held off for having declined a
/// session while busy ([`crate::data::network::Network::refused_peers`]). A
/// close group too few of which answered, some of the rest busy, fails with
/// "busy; try again shortly" rather than a shortfall ([`ReadTally::outcome`]).
/// `held_off` lists the peers held off so when the read began. A lookup
/// leaves them out, so when one of them would rank among the close group the
/// lookup returned ([`displaces_the_group`]), the close group is not settled
/// early: every member is waited for, so that as many of the true group
/// answer as can ([`held_off_wait`]).
///
/// It also reports what the bootstrap peers said ([`PointerRead::seeds`]),
/// and which peers it asked and which answered ([`Contacted`]), from which
/// [`past_refusals`] tells whether peers held off as busy, and so left out
/// of the lookup, may hold a state it missed.
async fn read_pointer_with_seeds<L, G, GF>(
    address: &XorName,
    close_group: L,
    close_group_size: usize,
    bootstrap: &[(PeerId, Vec<MultiAddr>)],
    get: G,
    busy: impl Fn(&PeerId) -> bool,
    held_off: &[PeerId],
) -> PointerRead
where
    L: Future<Output = Result<Vec<(PeerId, Vec<MultiAddr>)>>>,
    G: Fn(PeerId, Vec<MultiAddr>) -> GF,
    GF: Future<Output = Result<Option<Pointer>>>,
{
    let ask = |peer: PeerId, addrs: Vec<MultiAddr>| {
        let reply = get(peer, addrs);
        async move { (peer, reply.await) }
    };
    if bootstrap.is_empty() {
        let peers = match close_group.await {
            Ok(peers) => peers,
            Err(failure) => {
                return PointerRead {
                    found: Err(failure),
                    seeds: None,
                    contacted: Contacted::default(),
                }
            }
        };
        let mut contacted = Contacted {
            asked: peers.iter().map(|(peer, _)| *peer).collect(),
            answered: HashSet::new(),
        };
        let in_flight = peers
            .iter()
            .map(|(peer, addrs)| ask(*peer, addrs.clone()))
            .collect();
        let width = quorum_width(peers.len(), close_group_size);
        let ask_all = displaces_the_group(address, close_group_size, &contacted.asked, held_off);
        let found = read_pointer_from(
            in_flight,
            width,
            address,
            Asked::CloseGroup,
            busy,
            ask_all,
            &mut contacted.answered,
        )
        .await
        .outcome;
        return PointerRead {
            found,
            seeds: None,
            contacted,
        };
    }
    let mut contacted = Contacted::default();
    let mut seeds = HashSet::new();
    let mut in_flight = FuturesUnordered::new();
    for (peer, addrs) in bootstrap {
        if seeds.insert(*peer) {
            contacted.asked.insert(*peer);
            in_flight.push(ask(*peer, addrs.clone()));
        }
    }
    let mut lookup = Some(Box::pin(close_group));
    // The close group's read, once the lookup has returned.
    let mut close: Option<Result<ReadTally>> = None;
    let mut members = HashSet::new();
    let mut close_waiting = 0usize;
    let mut close_done = false;
    // Whether the close group is read to the end, since peers held off may
    // be among it.
    let mut ask_all = false;
    let mut boot = ReadTally::new(seeds.len());
    let mut boot_waiting = seeds.len();
    let mut boot_done = false;
    // Bootstrap peers' replies from before the close group was known, since
    // any of them may be in it.
    let mut early = Vec::new();
    loop {
        if !close_done {
            close_done = match &close {
                Some(Ok(tally)) => (tally.settled() && !ask_all) || close_waiting == 0,
                Some(Err(_)) => true,
                None => false,
            };
        }
        if !boot_done {
            let close_state = match &close {
                Some(Ok(tally)) if close_done => tally.state(),
                _ => None,
            };
            boot_done = boot_waiting == 0
                || boot.state().is_some()
                || close_state
                    .is_some_and(|held| boot.has_quorum() && !boot.names_newer_than(held));
        }
        if (close_done && boot_done) || (lookup.is_none() && in_flight.is_empty()) {
            break;
        }
        let event = {
            let looked_up = async {
                match lookup.as_mut() {
                    Some(lookup) => lookup.await,
                    None => futures::future::pending().await,
                }
            };
            let replied = async {
                match in_flight.next().await {
                    Some(reply) => reply,
                    None => futures::future::pending().await,
                }
            };
            match select(Box::pin(looked_up), Box::pin(replied)).await {
                Either::Left((found, _)) => Either::Left(found),
                Either::Right((reply, _)) => Either::Right(reply),
            }
        };
        match event {
            Either::Left(found) => {
                lookup = None;
                close = Some(found.map(|peers| {
                    members = peers.iter().map(|(peer, _)| *peer).collect();
                    ask_all = displaces_the_group(address, close_group_size, &members, held_off);
                    let mut tally = ReadTally::new(quorum_width(members.len(), close_group_size));
                    close_waiting = members.len();
                    for (peer, reply) in early.drain(..) {
                        if members.contains(&peer) {
                            close_waiting = close_waiting.saturating_sub(1);
                            match reply {
                                Ok(found) => tally.answer(found),
                                Err(e) => tally.fail(e, busy(&peer)),
                            }
                        }
                    }
                    if ask_all || !tally.settled() {
                        for (peer, addrs) in peers {
                            if !seeds.contains(&peer) && contacted.asked.insert(peer) {
                                in_flight.push(ask(peer, addrs));
                            }
                        }
                    }
                    tally
                }));
            }
            Either::Right((peer, reply)) => {
                if reply.is_ok() {
                    contacted.answered.insert(peer);
                }
                let seed = seeds.contains(&peer);
                if seed {
                    boot_waiting = boot_waiting.saturating_sub(1);
                    if let Err(e) = &reply {
                        debug!(
                            "pointer GET for {} to bootstrap peer {peer} failed: {e}",
                            hex::encode(address)
                        );
                    }
                }
                if seed && !boot_done {
                    if let Ok(found) = &reply {
                        boot.answer(found.clone());
                    }
                }
                match &mut close {
                    None if seed => early.push((peer, reply)),
                    Some(Ok(tally)) if members.contains(&peer) => {
                        close_waiting = close_waiting.saturating_sub(1);
                        if !close_done {
                            match reply {
                                Ok(found) => tally.answer(found),
                                Err(e) => tally.fail(e, busy(&peer)),
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let close = match close {
        Some(Ok(tally)) => tally.finish(address, Asked::CloseGroup),
        Some(Err(failure)) => SetRead {
            outcome: Err(failure),
            seen: None,
        },
        None => SetRead {
            outcome: Err(Error::Protocol(
                "no close-group peer answered for the pointer".to_string(),
            )),
            seen: None,
        },
    };
    let seeds = boot.seeds_view();
    PointerRead {
        found: newest_pointer(close, boot.finish(address, Asked::Bootstrap)),
        seeds: Some(seeds),
        contacted,
    }
}

/// Combine a read of the close group with a read of the bootstrap peers, each
/// on its own quorum and corroboration ([`ReadTally`]).
///
/// - Both sets return a state: the newer one by the merge rule
///   ([`Pointer::replaces`]).
/// - Only the bootstrap peers return one: theirs, even when the close group
///   does not answer, falls short or holds none.
/// - Neither returns one: the close group's outcome, absence or failure,
///   unchanged.
///
/// Either set's state is verified against the address and its owner's
/// signature, and corroborated within that set. A set too few of whose peers
/// answered still reports the state its answers corroborate, and the read never
/// returns anything that state replaces, absence included: it fails with that
/// set's shortfall instead, as a read of that set alone would. So an older
/// state from one set never rolls back a newer one from the other.
///
/// Two final states that no majority of a set holds are a fork
/// ([`Error::PointerForked`]). The close group's fork is the read's answer,
/// whatever the bootstrap peers name. The bootstrap peers' fork is the answer
/// only when the close group answered and holds no final state: a final state
/// it holds stands, since no final state replaces another. A close group that
/// failed reports its own failure, as it does beside any other failure of the
/// bootstrap peers.
fn newest_pointer(close_group: SetRead, bootstrap: SetRead) -> Result<Option<Pointer>> {
    // Whether a set's corroborated state replaces what the read would return.
    let replaces = |seen: &Option<Pointer>, held: Option<&Pointer>| {
        seen.as_ref()
            .is_some_and(|seen| held.is_none_or(|held| seen.replaces(held)))
    };
    let from_bootstrap = |other: Pointer| -> Result<Option<Pointer>> {
        debug!(
            "pointer {} read from the bootstrap peers at counter {}: the close group \
             gave no state",
            hex::encode(other.address()),
            other.counter()
        );
        Ok(Some(other))
    };
    match (close_group.outcome, bootstrap.outcome) {
        (Ok(Some(held)), Ok(Some(other))) => {
            Ok(Some(if other.replaces(&held) { other } else { held }))
        }
        (Ok(held), Ok(None)) => Ok(held),
        (Ok(held), Err(fork @ Error::PointerForked(_))) => {
            if held.as_ref().is_some_and(Pointer::is_terminal) {
                debug!(
                    "the bootstrap peers report a fork of a pointer whose close group \
                     holds a final state, which stands: {fork}"
                );
                Ok(held)
            } else {
                Err(fork)
            }
        }
        (Ok(held), Err(failure)) => {
            debug!("the bootstrap peers gave no state for a pointer: {failure}");
            if replaces(&bootstrap.seen, held.as_ref()) {
                Err(failure)
            } else {
                Ok(held)
            }
        }
        (Ok(None), Ok(Some(other))) => from_bootstrap(other),
        (Err(fork @ Error::PointerForked(_)), _) => Err(fork),
        (Err(failure), Ok(Some(other))) => {
            if replaces(&close_group.seen, Some(&other)) {
                Err(failure)
            } else {
                from_bootstrap(other)
            }
        }
        (Err(failure), other) => {
            if let Err(e) = other {
                debug!("the bootstrap peers gave no state for a pointer: {e}");
            }
            Err(failure)
        }
    }
}

/// Whether a pointer write that failed this way may succeed if tried again
/// with the same proof: a shortfall, an unreachable group, or a node that
/// could not store it just then, not a refusal of the record itself.
///
/// A node answering with an error reports its own condition, such as a full
/// disk or too many checks running, not a verdict on a record this client
/// signed and paid for, so other peers may still take the same proof.
fn worth_retrying(error: &Error) -> bool {
    matches!(
        error,
        Error::CloseGroupShortfall(_)
            | Error::Network(_)
            | Error::Timeout(_)
            | Error::InsufficientPeers(_)
            | Error::RemotePut { .. }
    )
}

/// What one peer's reply means for a write.
///
/// `None` means the message was not a reply to this request at all, and the
/// caller keeps waiting.
///
/// A storer that acknowledges some *other* record is claiming to hold something
/// this client never sent. Taking that at face value would let one peer end the
/// write — after payment — while storing nothing, so an acknowledgement only
/// counts when it names the record that was sent.
fn read_put_reply(
    body: ChunkMessageBody,
    expected_address: XorName,
    expected_state: XorName,
) -> Option<Result<PutAck>> {
    let ChunkMessageBody::PointerPutResponse(response) = body else {
        return None;
    };
    Some(match response {
        // `Unchanged` is success for a retry: the state the client signed is
        // exactly what the node holds.
        PointerPutResponse::Success { address, state_id }
        | PointerPutResponse::Unchanged { address, state_id } => {
            if address == expected_address && state_id == expected_state {
                Ok(PutAck::Stored)
            } else {
                Err(Error::InvalidData(format!(
                    "peer acknowledged a pointer this client did not send: address {} state {}",
                    hex::encode(address),
                    hex::encode(state_id)
                )))
            }
        }
        // Every reply names the address it is about, and every one of them is
        // checked against the address that was sent. A refusal is not exempt:
        // one about some other pointer says nothing about this write.
        // A claim, about this pointer, that it has moved on. Whether it has
        // is for a read to confirm (see [`judge_write`]).
        PointerPutResponse::Stale { address, .. } if address == expected_address => {
            Ok(PutAck::Stale)
        }
        PointerPutResponse::Stale { address, .. } => Err(Error::InvalidData(format!(
            "peer refused a pointer this client did not send: address {}",
            hex::encode(address)
        ))),
        PointerPutResponse::PaymentRequired { message } => Err(Error::Payment(message)),
        // The node's own reason, kept as it gave it: a node that could not
        // store the record is a shortfall to retry, not a refusal of it.
        PointerPutResponse::Error(e) => Err(Error::RemotePut {
            address: hex::encode(expected_address),
            source: e,
        }),
    })
}

/// What one peer's reply means for a read.
///
/// Verify before trusting: the signature must check out and the record must
/// belong at the address that was asked for, or a storer could answer with
/// someone else's pointer, or with bytes nobody signed.
fn read_get_reply(body: ChunkMessageBody, address: XorName) -> Option<Result<Option<Pointer>>> {
    let ChunkMessageBody::PointerGetResponse(response) = body else {
        return None;
    };
    Some(match response {
        PointerGetResponse::Success { record } => match Pointer::from_bytes(&record) {
            Ok(record) if record.address() == address => Ok(Some(record)),
            Ok(_) => Err(Error::InvalidData(
                "peer answered with a pointer for a different address".to_string(),
            )),
            Err(e) => Err(Error::InvalidData(format!("invalid pointer: {e}"))),
        },
        // "I do not have it" still has to be about the address that was asked
        // for, exactly as an acknowledgement does: an answer naming something
        // else is not an answer to this request.
        PointerGetResponse::NotFound { address: absent } => {
            if absent == address {
                Ok(None)
            } else {
                Err(Error::InvalidData(format!(
                    "peer reported a different address absent: {}",
                    hex::encode(absent)
                )))
            }
        }
        PointerGetResponse::Error(e) => Err(Error::Protocol(format!("pointer GET refused: {e}"))),
    })
}

/// How many pointer hops [`Client::pointer_resolve`] will follow.
///
/// A pointer may target another pointer — that is how handover works — so a
/// chain can be arbitrarily long, and a malicious or careless owner can make it
/// a cycle. The node cannot stop either: it never reads the target. So the
/// client bounds it.
pub const MAX_POINTER_RESOLVE_DEPTH: usize = 16;

/// Refuse a recipient that does not exist or whose chain leads back to
/// `address`.
///
/// A transfer to a pointer nobody created redirects every reader into a
/// broken chain, and one that leads back here is a cycle; either is final
/// the moment it is stored. The chain is followed as it stands now: the
/// recipient can still move its own pointer later, and a read that meets
/// a cycle then refuses it as it would any other.
///
/// A reader of `address` reads it first and then every pointer from the
/// recipient on, so the recipient's chain gets one hop fewer than
/// [`MAX_POINTER_RESOLVE_DEPTH`]. A chain still going after that is
/// refused: readers could not resolve it, and whether it leads back here
/// is past what can be checked.
async fn check_recipient_chain<Get, Fut>(
    address: &XorName,
    recipient: &XorName,
    get: Get,
) -> Result<()>
where
    Get: Fn(XorName) -> Fut,
    Fut: Future<Output = Result<Option<Pointer>>>,
{
    let mut at = *recipient;
    let mut seen = HashSet::new();
    for hop in 0..MAX_POINTER_RESOLVE_DEPTH.saturating_sub(1) {
        if at == *address {
            return Err(Error::InvalidData(format!(
                "recipient pointer {} leads back to pointer {}; the transfer would be a \
                 cycle",
                hex::encode(recipient),
                hex::encode(address)
            )));
        }
        if !seen.insert(at) {
            return Ok(());
        }
        let Some(record) = get(at).await? else {
            if hop == 0 {
                return Err(Error::InvalidData(format!(
                    "recipient pointer {} does not exist; its owner must create it before \
                     it can receive a transfer",
                    hex::encode(recipient)
                )));
            }
            return Ok(());
        };
        let target = record.target();
        match target.kind() {
            Some(PointerTargetKind::Pointer) => at = target.address,
            _ => return Ok(()),
        }
    }
    if at == *address {
        return Err(Error::InvalidData(format!(
            "recipient pointer {} leads back to pointer {}; the transfer would be a cycle",
            hex::encode(recipient),
            hex::encode(address)
        )));
    }
    Err(Error::InvalidData(format!(
        "recipient pointer {} starts a chain longer than {} hops; readers of pointer {} \
         could not follow the transfer",
        hex::encode(recipient),
        MAX_POINTER_RESOLVE_DEPTH.saturating_sub(1),
        hex::encode(address)
    )))
}

/// Follow the pointer chain from `address`, reading each pointer with `get`,
/// to the first target that is not a pointer: [`Client::pointer_resolve`]'s
/// walk, refusing a cycle, a missing hop and a chain longer than
/// [`MAX_POINTER_RESOLVE_DEPTH`].
async fn resolve_chain<Get, Fut>(address: &XorName, get: Get) -> Result<PointerTarget>
where
    Get: Fn(XorName) -> Fut,
    Fut: Future<Output = Result<Option<Pointer>>>,
{
    let mut seen = HashSet::new();
    let mut at = *address;

    for _ in 0..MAX_POINTER_RESOLVE_DEPTH {
        if !seen.insert(at) {
            return Err(Error::InvalidData(format!(
                "pointer chain cycles back to {}",
                hex::encode(at)
            )));
        }
        let record = get(at).await?.ok_or_else(|| {
            Error::InvalidData(format!("pointer chain breaks at {}", hex::encode(at)))
        })?;
        let target = record.target();
        match target.kind() {
            Some(PointerTargetKind::Pointer) => at = target.address,
            Some(PointerTargetKind::Chunk) => return Ok(target),
            // A tag this build does not know. The bytes are authentic — the
            // record is signed — so report the target rather than pretend
            // the chain is broken; the caller decides what to do with it.
            None => return Ok(target),
        }
    }
    Err(Error::InvalidData(format!(
        "pointer chain from {} is longer than {MAX_POINTER_RESOLVE_DEPTH} hops",
        hex::encode(address)
    )))
}

impl Client {
    /// Create a pointer at counter 0, owned by `owner`.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails, payment fails, or fewer peers than
    /// the write quorum store the record.
    pub async fn pointer_create(
        &self,
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        target: PointerTarget,
    ) -> Result<XorName> {
        let record = self.pointer_sign_create(secret_key, owner, target).await?;
        self.pointer_put(&record).await
    }

    /// Sign the record that creates `owner`'s pointer, after checking the
    /// network holds none.
    ///
    /// Checked before anything is paid: a second creation would pay again for
    /// a state the network either already holds, and answers as unchanged, or
    /// has moved past, and refuses as stale. Either way the payment buys
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the pointer already exists, if the network cannot
    /// say whether it does, or if signing fails.
    pub async fn pointer_sign_create(
        &self,
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        target: PointerTarget,
    ) -> Result<Pointer> {
        let address = pointer_address(owner);
        if let Some(existing) = self.pointer_get(&address).await? {
            return Err(Error::InvalidData(format!(
                "pointer {} already exists at counter {}; update it instead",
                hex::encode(address),
                existing.counter()
            )));
        }
        Pointer::create(secret_key, owner, target)
            .map_err(|e| Error::InvalidData(format!("cannot sign pointer: {e}")))
    }

    /// Update the pointer owned by `owner` to `target`, at `counter + 1`.
    ///
    /// Reads the current record first, because the update has to beat what the
    /// network serves: it is signed one past that counter. A pointer that does
    /// not exist yet is created at 0.
    ///
    /// # Errors
    ///
    /// Returns an error if the current record cannot be read, the counter is
    /// exhausted, signing fails, payment fails, or fewer peers than the write
    /// quorum store it.
    pub async fn pointer_update(
        &self,
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        target: PointerTarget,
    ) -> Result<XorName> {
        let record = self.pointer_sign_update(secret_key, owner, target).await?;
        self.pointer_put(&record).await
    }

    /// Sign the record that updates `owner`'s pointer to `target`, without
    /// storing it: one past the counter the network serves, or a creation at 0
    /// if it serves none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PointerFinal`] or [`Error::PointerForked`] if any peer
    /// of the close group holds a final state for the pointer, even one too
    /// few peers hold for a read to return; otherwise an error if the group
    /// cannot be asked, the current record cannot be read, or signing fails.
    pub async fn pointer_sign_update(
        &self,
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        target: PointerTarget,
    ) -> Result<Pointer> {
        let address = pointer_address(owner);
        // A final state even one peer holds was signed by the owner, and no
        // node holding it will take this update: a transfer or freeze that
        // fell short. A read settles once enough peers agree, before a slow
        // peer holding it may have answered, so the whole group is asked:
        // finish the final state rather than move the rest of the group
        // somewhere those nodes never follow. An update can be replaced, so a
        // peer that does not answer does not hold it up. The close group
        // alone is asked: the read below asks the bootstrap peers too.
        let finality = self.close_group_finality(&address).await?;
        if let Some(refusal) = final_already(&finality) {
            return Err(refusal);
        }
        match self.pointer_get(&address).await? {
            Some(current) => current.update(secret_key, target).map_err(|e| match e {
                PointerError::CounterExhausted => Error::PointerFinal(format!(
                    "pointer {} holds {}; nothing can update it",
                    hex::encode(address),
                    describe_final(&current)
                )),
                e => Error::InvalidData(format!("cannot sign pointer update: {e}")),
            }),
            None => Pointer::create(secret_key, owner, target)
                .map_err(|e| Error::InvalidData(format!("cannot sign pointer: {e}"))),
        }
    }

    /// Hand the pointer owned by `owner` over to the pointer at `recipient`,
    /// for good, and report where the transfer stands.
    ///
    /// Signs the pointer's final state, pointing at `recipient`, pays for it
    /// and stores it (ADR-0018 in `ant-node`). A final state is replaced by
    /// nothing, so from then on every reader of this address is redirected to
    /// the recipient's pointer, which only its owner can move, and this key
    /// can change nothing. The address readers use stays the same.
    ///
    /// The recipient should create a pointer with a fresh key for each address
    /// it receives: a pointer's address derives from its key, so every address
    /// handed to one recipient pointer resolves to the same place.
    ///
    /// Once the write has landed the whole close group is asked where the
    /// transfer stands. That check is reported beside the transfer, not as its
    /// outcome: a check that fails after the write says nothing about a
    /// transfer that is already stored and final. A recipient should check it
    /// with [`Self::pointer_finality`] itself before relying on the transfer.
    ///
    /// # Errors
    ///
    /// As [`Self::pointer_sign_transfer`] before anything is paid; then as
    /// [`Self::pointer_put`], except that a write refused because the pointer
    /// was already final elsewhere is reported as [`Error::PointerFinal`] or
    /// [`Error::PointerForked`].
    pub async fn pointer_transfer(
        &self,
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        recipient: XorName,
    ) -> Result<PointerTransfer> {
        let record = self
            .pointer_sign_transfer(secret_key, owner, recipient)
            .await?;
        let address = record.address();
        if let Err(e) = self.pointer_put(&record).await {
            // Nodes refuse a final state when they hold, or their group
            // proves, a different one; and a write whose acknowledgements
            // were lost may have landed all the same. The group says which.
            let finality = self.recover_final_write(&record, e).await?;
            return Ok(PointerTransfer {
                address,
                state_id: record.state_id(),
                finality: Ok(finality),
            });
        }
        Ok(PointerTransfer {
            address,
            state_id: record.state_id(),
            finality: self.pointer_finality(&address).await,
        })
    }

    /// Whether the final state `record`, whose write reported `error`, landed
    /// anyway: the group holding it on a majority means its acknowledgements
    /// were lost, not the write. See [`after_failed_transfer`].
    ///
    /// # Errors
    ///
    /// The rival final state that refused it, or `error` itself when the
    /// group does not show the record held by a majority.
    pub(crate) async fn recover_final_write(
        &self,
        record: &Pointer,
        error: Error,
    ) -> Result<PointerFinality> {
        let finality = self.close_group_finality(&record.address()).await;
        after_failed_transfer(error, finality, record)
    }

    /// Sign the final state that hands `owner`'s pointer over to the pointer
    /// at `recipient`, without storing it.
    ///
    /// Everything that can be checked is checked before it is stored, because
    /// once a final state is stored it cannot be taken back: the pointer must
    /// not be final already, the recipient must not be the pointer itself, the
    /// recipient pointer must exist, and following it must not lead back
    /// here.
    ///
    /// "Final already" is asked of the whole close group, as
    /// [`Self::pointer_finality`] asks it, not of an ordinary read (the read
    /// made first asks the bootstrap peers too). A read returns a
    /// state only once two peers name it, so a final state an earlier
    /// transfer left on one peer is not what it returns, and signing a second
    /// final state past that one would fork the pointer for good. Any final
    /// state other than the one signed here refuses the transfer; the same
    /// state, left by an earlier attempt at this very transfer, does not. A
    /// silent peer could hold one, so a transfer goes ahead only when every
    /// peer of the configured close group answered.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PointerFinal`] if the pointer is already final, or
    /// [`Error::PointerForked`] if its owner already forked it,
    /// [`Error::InvalidData`] for a recipient that is this pointer, does not
    /// exist or leads back to it, [`Error::CloseGroupShortfall`] if not every
    /// peer of the group answered, or an error if either pointer cannot be
    /// read or signing fails.
    pub async fn pointer_sign_transfer(
        &self,
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        recipient: XorName,
    ) -> Result<Pointer> {
        let address = pointer_address(owner);
        if recipient == address {
            return Err(Error::InvalidData(format!(
                "pointer {} cannot be handed over to itself",
                hex::encode(address)
            )));
        }
        let current = self.pointer_get(&address).await?;
        if let Some(current) = current.as_ref().filter(|record| record.is_terminal()) {
            return Err(Error::PointerFinal(format!(
                "pointer {} already holds {}",
                hex::encode(address),
                describe_final(current)
            )));
        }
        self.check_recipient(&address, &recipient).await?;

        let target = PointerTarget::new(PointerTargetKind::Pointer, recipient);
        let record = match current {
            Some(current) => current.transfer_to(secret_key, recipient),
            None => Pointer::sign(secret_key, owner, FINAL_COUNTER, target),
        }
        .map_err(|e| Error::InvalidData(format!("cannot sign pointer transfer: {e}")))?;

        let finality = self.close_group_finality(&address).await?;
        if let Some(refusal) = rival_final(&finality, &record) {
            return Err(refusal);
        }
        // A transfer cannot be taken back, so no final state being seen is
        // only enough when every peer of the group was asked and answered.
        if finality.answered < finality.group {
            return Err(Error::CloseGroupShortfall(format!(
                "only {} of the {} peers of pointer {}'s close group answered, and a silent \
                 one could hold a final state; a transfer cannot be taken back, so try again \
                 when all of them can be asked",
                finality.answered,
                finality.group,
                hex::encode(address)
            )));
        }
        Ok(record)
    }

    /// Refuse a recipient that does not exist or whose chain leads back to
    /// `address` (see [`check_recipient_chain`]).
    async fn check_recipient(&self, address: &XorName, recipient: &XorName) -> Result<()> {
        check_recipient_chain(address, recipient, |at| async move {
            self.pointer_get(&at).await
        })
        .await
    }

    /// Ask the whole close group where `address` stands with respect to
    /// finality, and, while it shows the pointer open, the bootstrap peers
    /// nearest it too.
    ///
    /// Unlike [`Self::pointer_get`], this does not stop once it has an answer:
    /// every peer is asked, within its own deadline, so a second final state
    /// held by even one of them is seen. That is what a recipient needs before
    /// relying on a transfer — [`FinalityStatus::Final`] means one final state,
    /// held by a majority, with every peer of the configured close group
    /// answering and none holding a rival. A group that did not all answer
    /// can show at most [`FinalityStatus::Unconfirmed`]. Final, unconfirmed,
    /// settling and forked are the close group's to decide.
    ///
    /// When no peer of the close group that answered holds a final state,
    /// the pointer is then read as [`Self::pointer_get`] reads it, from the
    /// close group and the bootstrap peers its lookup leaves among the nine
    /// nearest, so a state only they hold is not missed: the census and the
    /// read share one lookup. The pointer is reported open at the counter of the
    /// state that read returns, settling on a final state only the bootstrap
    /// peers hold, and open with no state only when neither set holds one,
    /// once every bootstrap peer asked has answered or failed
    /// ([`PointerFinality::seeds`] says what they hold).
    ///
    /// A browser leaves peers held off for having declined a session while
    /// busy out of the lookup, so farther peers answer in their place. While
    /// such peers may be the close group and the check shows the pointer
    /// open, or fails in a way they explain (too few answering or naming one
    /// state, or busy), it is made again once their hold-off ends, as a read
    /// is ([`past_refusals`]). A final state every peer asked holds, while
    /// such a peer ranks in the group unasked, is
    /// [`FinalityStatus::Unconfirmed`].
    ///
    /// # Errors
    ///
    /// Returns an error if no peer is responsible for the address, if too
    /// few of the group answer to speak for it, or, when the pointer is open,
    /// with the error that read gives; and that the nodes that may hold the
    /// pointer are busy when peers held off may still hold it after the
    /// waits.
    pub async fn pointer_finality(&self, address: &XorName) -> Result<PointerFinality> {
        let close_group_size = self.config().close_group_size;
        past_refusals(
            address,
            close_group_size,
            || self.network().refused_peers(),
            finality_is_open,
            || async move {
                let held_off = self.held_off_peers();
                // One lookup serves the census and the read after it, and
                // decides which bootstrap peers that read asks.
                let group = match self.pointer_group(address).await {
                    Ok(group) => group,
                    Err(failure) => return (Err(failure), Contacted::default()),
                };
                let bootstrap = seeds_beside(
                    Some(&group),
                    self.network().bootstrap_peers_near(address),
                    address,
                );
                pointer_finality_from(
                    address,
                    || std::future::ready(Ok(group.clone())),
                    close_group_size,
                    &bootstrap,
                    |peer, addrs| self.send_pointer_get(*address, peer, addrs),
                    |peer| self.held_off_busy(peer),
                    &held_off,
                )
                .await
            },
        )
        .await
    }

    /// Ask the whole close group where `address` stands with respect to
    /// finality, and no bootstrap peer: [`Self::pointer_finality`]'s census
    /// on its own, which the checks an update and a transfer make before
    /// paying use, as does a transfer whose write reported failure. While
    /// peers held off as busy may be the close group and it shows the
    /// pointer open, or too few of the group answered, it is taken again
    /// once their hold-off ends ([`past_refusals`]). A final state every peer
    /// asked holds, while such a peer ranks in the group unasked, is
    /// [`FinalityStatus::Unconfirmed`].
    ///
    /// # Errors
    ///
    /// Returns an error if no peer is responsible for the address, if too
    /// few of the group answer to speak for it, or that the nodes that may
    /// hold the pointer are busy.
    pub(crate) async fn close_group_finality(&self, address: &XorName) -> Result<PointerFinality> {
        let close_group_size = self.config().close_group_size;
        past_refusals(
            address,
            close_group_size,
            || self.network().refused_peers(),
            finality_is_open,
            || async move {
                let held_off = self.held_off_peers();
                let (census, contacted) = close_group_census(
                    address,
                    self.pointer_group(address),
                    close_group_size,
                    |peer, addrs| self.send_pointer_get(*address, peer, addrs),
                    &held_off,
                )
                .await;
                (census.map(|(finality, _)| finality), contacted)
            },
        )
        .await
    }

    /// Follow `address` through every transfer to the pointer whose owner now
    /// decides what it resolves to.
    ///
    /// Only transfers are followed — final states targeting a pointer. A
    /// pointer target below the final counter is a forwarding its owner can
    /// still take back, so that owner still decides, and the walk stops there.
    ///
    /// # Errors
    ///
    /// Returns an error if a pointer on the way is missing or unreadable, if
    /// the transfers cycle, or if they are longer than
    /// [`MAX_POINTER_RESOLVE_DEPTH`].
    pub async fn pointer_controller(&self, address: &XorName) -> Result<PointerController> {
        let mut seen = HashSet::new();
        let mut transfers = Vec::new();
        let mut at = *address;
        for _ in 0..MAX_POINTER_RESOLVE_DEPTH {
            if !seen.insert(at) {
                return Err(Error::InvalidData(format!(
                    "pointer transfers cycle back to {}",
                    hex::encode(at)
                )));
            }
            let record = self
                .pointer_get(&at)
                .await?
                .ok_or_else(|| Error::NotFound(format!("no pointer at {}", hex::encode(at))))?;
            match record.transferred_to() {
                Some(next) => {
                    transfers.push(next);
                    at = next;
                }
                None => {
                    return Ok(PointerController {
                        pointer: at,
                        transfers,
                        frozen: record.is_terminal(),
                    })
                }
            }
        }
        Err(Error::InvalidData(format!(
            "pointer transfers from {} are longer than {MAX_POINTER_RESOLVE_DEPTH} hops",
            hex::encode(address)
        )))
    }

    /// Pay for and store an already-signed pointer.
    ///
    /// Each call settles a payment for the state it is given, unless an
    /// earlier call with the same wallet paid for that state and didn't store
    /// it. The payment is journaled and recovered as
    /// [`Client::pay_for_storage_split`] describes, and its proof is kept in
    /// the state's payment checkpoint until the state is stored, so a call
    /// that failed after paying, such as a write that fell short, is retried
    /// by calling again with the same record, without paying again. A state
    /// the network already holds is answered as stored, but once its
    /// checkpoint is gone a call pays for it again: read first if that
    /// matters; the node cannot tell a retry from a fresh submission before
    /// it has been paid to look. Browser builds journal and keep nothing, so
    /// each of their calls pays.
    ///
    /// # Errors
    ///
    /// Returns an error if no peer is responsible for the address, if payment
    /// fails, or if fewer peers than the write quorum store the record.
    pub async fn pointer_put(&self, record: &Pointer) -> Result<XorName> {
        let address = record.address();
        let state_id = record.state_id();

        // Refuse before paying if nobody is responsible for this address, or
        // too few of those who are can take the write. There is no sense
        // buying storage with nowhere to put it, and a quorum of nothing would
        // otherwise be satisfied by nothing — a paid write reported as stored
        // on zero peers.
        self.pointer_write_group(&address).await?;

        // The quote names the state; the peers that may issue it are the close
        // group around the address. One payment, one state. The payment has
        // read its quote's vault record back already.
        #[cfg(feature = "native")]
        {
            let paid = self
                .pay_for_record(
                    &address,
                    &state_id,
                    POINTER_WIRE_LEN as u64,
                    DATA_TYPE_POINTER,
                    crate::data::client::payment::declared_size_weight(DATA_TYPE_POINTER),
                )
                .await?;
            let stored = self
                .pointer_put_paid_unchecked(record, paid.proof.clone())
                .await?;
            paid.stored();
            Ok(stored)
        }
        #[cfg(not(feature = "native"))]
        {
            let (proof, _) = self
                .pay_for_storage_split(
                    &address,
                    &state_id,
                    POINTER_WIRE_LEN as u64,
                    DATA_TYPE_POINTER,
                )
                .await?;
            self.pointer_put_paid_unchecked(record, proof).await
        }
    }

    /// Quote a signed pointer's state for a payer outside this client, such as
    /// a browser wallet or another external signer, without paying.
    ///
    /// Pay the plan's median quote, build the proof with
    /// [`ChunkPaymentPlan::proof`], then store with [`Self::pointer_put_paid`].
    ///
    /// The state is quoted for the per-quote vault, even on a client paying
    /// the root vault ([`Self::with_root_payments`]): the plan is paid one
    /// quote at a time, never in a root wave.
    ///
    /// # Errors
    ///
    /// Returns an error if no peer is responsible for the address, or if too
    /// few acceptable quotes come back.
    pub async fn prepare_pointer_payment(&self, record: &Pointer) -> Result<ChunkPaymentPlan> {
        let address = record.address();
        // As for a wallet payment: nothing is quoted with nowhere to store it.
        self.pointer_write_group(&address).await?;
        // The per-quote vault, whatever vault this client pays: the payer
        // outside the client pays the median quote and `ChunkPaymentPlan::proof`
        // builds a per-quote proof. Quoted for the root vault, the state would
        // ask settlement version 3 for nothing, and a close group holding a
        // storer that can't check a root proof would cost a second round.
        self.prepare_payment_plan_split(
            &address,
            &record.state_id(),
            POINTER_WIRE_LEN as u64,
            DATA_TYPE_POINTER,
            crate::data::client::payment::declared_size_weight(DATA_TYPE_POINTER),
            crate::data::client::root_payment::PaymentVault::V2,
        )
        .await
    }

    /// Store a signed pointer with a proof already paid for its state.
    ///
    /// The second half of [`Self::pointer_put`], for a proof paid outside this
    /// client. It is also how to retry a write that fell short without paying
    /// again: the proof stays valid for its state, and a node that already
    /// holds that state answers as stored.
    ///
    /// The proof's paid quote is read back from the vault before the state is
    /// sent. If the vault had already recorded the quote for another payment,
    /// it skipped this one, and nodes would refuse the state: nothing is sent,
    /// and the state has to be quoted ([`Self::prepare_pointer_payment`]) and
    /// paid again. The read-back goes through the client's EVM network
    /// (`with_wallet` or `with_evm_network`): a native client with neither
    /// reads nothing back and logs a warning. Browser builds read nothing back.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof isn't a single-node payment proof, an
    /// error starting [`QUOTES_OCCUPIED`](crate::data::QUOTES_OCCUPIED)
    /// naming the node that issued the quote if it was occupied, or an error
    /// if no peer is responsible for the address or if too few of the close
    /// group accept the record.
    pub async fn pointer_put_paid(&self, record: &Pointer, proof: Vec<u8>) -> Result<XorName> {
        self.check_paid_pointer_proof(record, &proof).await?;
        self.pointer_put_paid_unchecked(record, proof).await
    }

    /// Refuse a proof for `record`'s state whose paid quote the vault had
    /// already recorded for another payment (see [`Self::pointer_put_paid`]).
    #[cfg(feature = "native")]
    async fn check_paid_pointer_proof(&self, record: &Pointer, proof: &[u8]) -> Result<()> {
        let plan = plan_of_proof(
            record.state_id(),
            POINTER_WIRE_LEN as u64,
            crate::data::client::payment::declared_size_weight(DATA_TYPE_POINTER),
            proof,
        )
        .map_err(|e| Error::Payment(format!("cannot read the pointer's payment proof: {e}")))?;
        let occupied = self.occupied_quotes(std::slice::from_ref(&plan)).await;
        if occupied.is_empty() {
            return Ok(());
        }
        let error = occupied_pointer_proof(&occupied);
        warn!("{error}");
        Err(error)
    }

    /// Browser builds read no records back: the wallet callback owns the RPC.
    #[cfg(not(feature = "native"))]
    async fn check_paid_pointer_proof(&self, _record: &Pointer, _proof: &[u8]) -> Result<()> {
        Ok(())
    }

    /// [`Self::pointer_put_paid`] without reading the paid quote back, for a
    /// proof whose payment already read it back ([`Self::pointer_put`]).
    async fn pointer_put_paid_unchecked(
        &self,
        record: &Pointer,
        proof: Vec<u8>,
    ) -> Result<XorName> {
        // A write that fell short is retried with the same proof, as a chunk
        // store is: peers that took it the first time answer `Unchanged`, which
        // counts, so each round only has to reach the ones that did not. A
        // refusal that says something definite, such as the payment was
        // refused or a peer acknowledged something else, is final only once a
        // second peer repeats it and nobody stored the record; a newer state
        // winning is final once a read confirms it (see [`judge_write`]). One
        // peer's refusal alone is retried like any shortfall.
        let mut attempt = 0;
        loop {
            match self.pointer_put_once(record, &proof).await {
                Ok(address) => return Ok(address),
                Err(e) if attempt < STORE_MAX_RETRIES && worth_retrying(&e) => {
                    attempt += 1;
                    warn!(
                        "pointer {} write fell short ({e}); retry {attempt}/{STORE_MAX_RETRIES}",
                        hex::encode(record.address())
                    );
                    sleep(store_retry_delay(attempt)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// One round of [`Self::pointer_put_paid`].
    async fn pointer_put_once(&self, record: &Pointer, proof: &[u8]) -> Result<XorName> {
        let address = record.address();
        let state_id = record.state_id();

        // Ask again rather than keep the set from before the payment. Settling
        // on chain takes time, and the peers responsible for an address can
        // change while it does; writing to the old set would then be refused by
        // peers that are no longer responsible while the ones that are were
        // never asked. The lookup above answered whether there was anywhere to
        // store this — this one answers where.
        let targets = self.pointer_group(&address).await?;
        let wanted = write_quorum(quorum_width(targets.len(), self.config().close_group_size));
        if targets.len() < wanted {
            return Err(Error::CloseGroupShortfall(format!(
                "found {} close-group peers for pointer {}, and a write needs {wanted}",
                targets.len(),
                hex::encode(address)
            )));
        }

        let request =
            PointerPutRequest::with_payment(Bytes::from(record.to_bytes()), proof.to_vec());
        let in_flight = FuturesUnordered::new();
        for (peer_id, addrs) in &targets {
            let request = request.clone();
            in_flight.push(self.send_pointer_put(
                request,
                *peer_id,
                addrs.clone(),
                address,
                state_id,
            ));
        }

        let (mut stored, mut stale) = (0usize, 0usize);
        let answered = ask_the_group(in_flight, wanted, |ack| {
            match ack {
                PutAck::Stored => stored += 1,
                PutAck::Stale => stale += 1,
            }
            stored >= wanted
        })
        .await;
        // Only a peer's word says the pointer moved on, so a read decides it
        // before the write is abandoned.
        let moved = stored < wanted && stale > 0 && self.moved_past(record).await;
        judge_write(&address, stored, wanted, moved, answered).map(|()| address)
    }

    /// Whether the network has moved past `record`: a read returns a state
    /// that replaces it, or, for a final state, a different final state,
    /// which nothing replaces either and which the group settled on instead.
    /// A read that fails says nothing, and counts as no.
    async fn moved_past(&self, record: &Pointer) -> bool {
        matches!(
            self.pointer_get(&record.address()).await,
            Ok(Some(current)) if current.replaces(record)
                || (record.is_terminal()
                    && current.is_terminal()
                    && current.state_id() != record.state_id())
        )
    }

    /// The peers a pointer write must land on and a read must ask.
    ///
    /// One definition serves both. A write acknowledged outside the set the
    /// read queries is a write nobody can read — paid for, stored, and
    /// invisible — so both go through here rather than each deciding for
    /// itself. In particular the payment plan's targets, which can run far
    /// wider than the close group, never count towards a write.
    ///
    /// Same definition, not the same answer: a read does its own lookup, so
    /// membership that changed in between is not covered here. That is churn,
    /// and what covers it is the nodes' replication, which hands a paid state to
    /// every member of the group that should hold it.
    async fn pointer_group(&self, address: &XorName) -> Result<Vec<(PeerId, Vec<MultiAddr>)>> {
        let peers = self
            .network()
            .find_closest_peers(address, self.config().close_group_size)
            .await?;
        if peers.is_empty() {
            // A lookup that succeeds and returns nobody is not somewhere a
            // pointer can live. Saying so here keeps every caller from having
            // to notice that a quorum of an empty group is zero.
            return Err(Error::CloseGroupShortfall(format!(
                "no peer is responsible for pointer {}",
                hex::encode(address)
            )));
        }
        Ok(peers)
    }

    /// The close group a write of `address` goes to, refused before anything
    /// is quoted or paid if too few of it would take the write.
    ///
    /// While nodes are being upgraded some of a close group may not store
    /// pointers yet. A browser can tell which from what each node advertises,
    /// and a write that fewer than a write quorum would take is otherwise paid
    /// for and then falls short. Only a node that says it would refuse counts
    /// against the write: one that cannot be asked in time might still take
    /// it, and the write finds out, as it did before. A native client cannot
    /// tell at all, and its write finds out as before.
    async fn pointer_write_group(
        &self,
        address: &XorName,
    ) -> Result<Vec<(PeerId, Vec<MultiAddr>)>> {
        let group = self.pointer_group(address).await?;
        let wanted = write_quorum(quorum_width(group.len(), self.config().close_group_size));
        // Too few found to reach a write quorum is a shortfall, whatever they
        // would say: no need to ask them.
        if group.len() < wanted {
            return Err(Error::CloseGroupShortfall(format!(
                "found {} close-group peers for pointer {}, and a write needs {wanted}; \
                 nothing was paid",
                group.len(),
                hex::encode(address)
            )));
        }
        let mut asked: FuturesUnordered<_> = group
            .iter()
            .map(|(peer, addrs)| self.network().accepts_pointer_writes(peer, addrs))
            .collect();
        let (mut taking, mut refusing) = (0usize, 0usize);
        while let Some(answer) = asked.next().await {
            match answer {
                Some(true) => taking += 1,
                Some(false) => refusing += 1,
                None => {}
            }
            if taking >= wanted {
                break;
            }
            if group.len().saturating_sub(refusing) < wanted {
                return Err(Error::InsufficientPeers(format!(
                    "{refusing} of the {} close-group peers for pointer {} do not accept \
                     pointer writes, so a write cannot reach the {wanted} it needs; nothing \
                     was paid",
                    group.len(),
                    hex::encode(address)
                )));
            }
        }
        // Enough would take it, or too few could be asked to be sure it
        // cannot land. Probes still out are dropped, which cancels them.
        drop(asked);
        Ok(group)
    }

    /// Read the pointer at `address`, verifying it before returning it.
    ///
    /// The record is checked against the address it was asked for, so a storer
    /// cannot answer with a different owner's pointer, and the state returned
    /// must be named by at least two of the peers that return it (by the one
    /// peer, in a set of one), so no single peer of a larger set decides what
    /// the pointer says. Once a final state is named, a set returns the final
    /// state a majority of it holds; two final states and no majority holding
    /// either are a fork, with no state to return.
    ///
    /// The close group is looked up, then asked, and at the same time so are
    /// the bootstrap peers that lookup leaves among the nine nearest the
    /// address, of the nine nearest of those the client knows by peer ID, or
    /// all nine when the lookup fails ([`seeds_beside`]), as a second set with
    /// its own quorum and corroboration (five answers and two naming the
    /// state, of nine); a peer in both is asked once. The close group's quorums are counted over the configured
    /// close-group size, or more peers if its lookup returned more. Its read
    /// does not stop on a state while a newer one has been named by too few
    /// peers to corroborate it, or on a final state too few hold to be a
    /// majority: it asks the rest of the group first. The answer is the newer
    /// state of the two sets, and a state the bootstrap peers name is returned
    /// even when the close group holds none or does not answer; see
    /// `read_pointer_with_seeds` and `newest_pointer`. The read then takes as long as the
    /// slower of the two sets, and reports the pointer absent only once each of
    /// those bootstrap peers has answered or failed. Without such bootstrap
    /// peers only the close group is asked.
    ///
    /// A browser leaves peers held off for having declined a session while
    /// busy out of the lookup, so farther peers answer in their place. While
    /// such peers may be the close group and too few of it answered, absence,
    /// a state that is not final, or a failure they explain (too few
    /// answering or naming one state, busy, or a fork no majority settles) is
    /// not the answer: the read is made again once their hold-off ends
    /// ([`past_refusals`]).
    ///
    /// # Errors
    ///
    /// Returns an error if no peer answers, if too few of the group do, or if
    /// the best state found has too few peers behind it to be the network's
    /// answer rather than one peer's, unless the bootstrap peers name a state.
    /// It also fails when too few of either set answered but those that did
    /// name a newer state than the read would otherwise return, and with
    /// [`Error::PointerForked`] when the close group names a fork, or the
    /// bootstrap peers do and the close group answered without a final state.
    /// It fails saying the nodes that may hold the pointer are busy when they
    /// are still held off after the waits.
    pub async fn pointer_get(&self, address: &XorName) -> Result<Option<Pointer>> {
        let close_group_size = self.config().close_group_size;
        past_refusals(
            address,
            close_group_size,
            || self.network().refused_peers(),
            read_is_open,
            || async move {
                let held_off = self.held_off_peers();
                let group = self.pointer_group(address).await;
                let bootstrap = seeds_beside(
                    group.as_deref().ok(),
                    self.network().bootstrap_peers_near(address),
                    address,
                );
                let read = read_pointer_with_seeds(
                    address,
                    std::future::ready(group),
                    close_group_size,
                    &bootstrap,
                    |peer, addrs| self.send_pointer_get(*address, peer, addrs),
                    |peer| self.held_off_busy(peer),
                    &held_off,
                )
                .await;
                (read.found, read.contacted)
            },
        )
        .await
    }

    /// Whether `peer` is held off for having declined a browser session while
    /// busy ([`crate::data::network::Network::refused_peers`]); a native
    /// client has none.
    fn held_off_busy(&self, peer: &PeerId) -> bool {
        self.network()
            .refused_peers()
            .iter()
            .any(|(refused, _)| refused == peer)
    }

    /// The peers held off now for having declined a browser session while
    /// busy ([`Self::held_off_busy`]).
    fn held_off_peers(&self) -> Vec<PeerId> {
        self.network()
            .refused_peers()
            .into_iter()
            .map(|(peer, _)| peer)
            .collect()
    }

    /// Follow a pointer chain to the chunk it ends at.
    ///
    /// A pointer may target another pointer, so this walks until it reaches a
    /// non-pointer target, refusing to loop or to walk further than
    /// [`MAX_POINTER_RESOLVE_DEPTH`]. Both guards live here because the node
    /// never reads a target and so cannot enforce either.
    ///
    /// A multi-hop read is not atomic: a target can move while the walk is in
    /// flight, so the result is what the chain said, not a snapshot of it.
    ///
    /// # Errors
    ///
    /// Returns an error if a hop is missing, the chain cycles, or the depth
    /// limit is reached. A target of a kind this build does not know is *not*
    /// an error: the record is signed, so the bytes are authentic, and the
    /// caller is handed the target to decide about.
    pub async fn pointer_resolve(&self, address: &XorName) -> Result<PointerTarget> {
        resolve_chain(address, |at| async move { self.pointer_get(&at).await }).await
    }

    /// Send one pointer PUT and check the acknowledgement against what was sent.
    ///
    /// A peer that answers `Success` for a different address or a different
    /// state is claiming to hold something the client never submitted. Taking
    /// that at face value would let one peer end the write — after payment —
    /// while storing nothing, so the reply has to name the record it was given.
    async fn send_pointer_put(
        &self,
        request: PointerPutRequest,
        target_peer: PeerId,
        peer_addrs: Vec<MultiAddr>,
        expected_address: XorName,
        expected_state: XorName,
    ) -> Result<PutAck> {
        let request_id = self.next_request_id();
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PointerPutRequest(request),
        };
        let bytes = message
            .encode()
            .map_err(|e| Error::Protocol(format!("cannot encode pointer PUT: {e}")))?;

        send_and_await_chunk_response(
            self.network(),
            &target_peer,
            bytes,
            request_id,
            // A pointer PUT carries a single-node proof — merkle proofs are
            // refused for pointers — so it does not make the storer do the
            // network closeness lookup the merkle timeout exists to cover.
            // Same budget as a non-merkle chunk PUT.
            STORE_RESPONSE_TIMEOUT,
            &peer_addrs,
            move |body| read_put_reply(body, expected_address, expected_state),
            |e| Error::Network(format!("pointer PUT send failed: {e}")),
            || Error::Timeout("pointer PUT timed out".to_string()),
        )
        .await
    }

    /// Send one pointer GET and validate whatever comes back.
    async fn send_pointer_get(
        &self,
        address: XorName,
        target_peer: PeerId,
        peer_addrs: Vec<MultiAddr>,
    ) -> Result<Option<Pointer>> {
        let request_id = self.next_request_id();
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PointerGetRequest(PointerGetRequest::new(address)),
        };
        let bytes = message
            .encode()
            .map_err(|e| Error::Protocol(format!("cannot encode pointer GET: {e}")))?;

        send_and_await_chunk_response(
            self.network(),
            &target_peer,
            bytes,
            request_id,
            Duration::from_secs(self.config().chunk_get_timeout_secs),
            &peer_addrs,
            move |body| read_get_reply(body, address),
            |e| Error::Network(format!("pointer GET send failed: {e}")),
            || Error::Timeout("pointer GET timed out".to_string()),
        )
        .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ant_protocol::pqc::api::ml_dsa_65;
    use futures::future::BoxFuture;
    use std::collections::HashMap;

    fn keypair(seed: u8) -> (MlDsaPublicKey, MlDsaSecretKey) {
        ml_dsa_65().generate_keypair_from_seed(&[seed; 32])
    }

    /// A write that fell short is retried with the proof already paid; one
    /// that was refused for a reason is not, since retrying cannot change it.
    #[test]
    fn only_a_shortfall_is_retried_with_the_same_proof() {
        for retried in [
            Error::CloseGroupShortfall("3 of 5".into()),
            Error::Network("unreachable".into()),
            Error::Timeout("slow".into()),
            Error::InsufficientPeers("none".into()),
        ] {
            assert!(worth_retrying(&retried), "{retried} must be retried");
        }
        for refused in [
            Error::InvalidData("the pointer moved while this update was in flight".into()),
            Error::Payment("valid payment is required".into()),
            Error::Protocol("pointer PUT refused".into()),
        ] {
            assert!(!worth_retrying(&refused), "{refused} must not be retried");
        }
    }

    fn chunk_target(byte: u8) -> PointerTarget {
        PointerTarget::new(PointerTargetKind::Chunk, [byte; 32])
    }

    /// A create is counter 0 and each update the client builds is one more,
    /// the smallest counter that beats the record it read.
    #[test]
    fn the_client_creates_at_zero_and_steps_by_one() {
        let (pk, sk) = keypair(1);
        let created = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        assert_eq!(created.counter(), 0);

        let mut current = created;
        for expected in 1..=5u64 {
            current = current.update(&sk, chunk_target(2)).expect("update");
            assert_eq!(current.counter(), expected);
        }
    }

    /// A pointer is public-key addressed: the address follows the owner key and
    /// nothing else, so a client can compute where its own pointer lives
    /// without asking the network.
    #[test]
    fn the_address_is_derivable_offline_from_the_owner_key() {
        let (pk, sk) = keypair(2);
        let record = Pointer::create(&sk, &pk, chunk_target(3)).expect("create");
        assert_eq!(record.address(), pointer_address(&pk));

        let (other, _) = keypair(3);
        assert_ne!(record.address(), pointer_address(&other));
    }

    /// Every update is a distinct paid state, so a receipt for one cannot fund
    /// another.
    #[test]
    fn each_update_is_paid_under_its_own_identifier() {
        let (pk, sk) = keypair(4);
        let created = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let next = created.update(&sk, chunk_target(2)).expect("update");
        let again = next.update(&sk, chunk_target(3)).expect("update");

        let states: std::collections::BTreeSet<_> = [&created, &next, &again]
            .iter()
            .map(|r| r.state_id())
            .collect();
        assert_eq!(states.len(), 3, "three updates, three paid identifiers");

        // And they all live at one address, which is what routing uses.
        assert_eq!(created.address(), next.address());
        assert_eq!(next.address(), again.address());
    }

    /// Every reply a peer can give to a read, fed to the code that judges them.
    #[test]
    fn a_read_refuses_every_reply_but_this_address_own_signed_record() {
        let (mine, my_sk) = keypair(5);
        let (theirs, their_sk) = keypair(6);
        let asked_for = pointer_address(&mine);
        let ours = Pointer::create(&my_sk, &mine, chunk_target(1)).expect("create");
        let theirs = Pointer::create(&their_sk, &theirs, chunk_target(1)).expect("create");

        let reply = |record: Bytes| {
            read_get_reply(
                ChunkMessageBody::PointerGetResponse(PointerGetResponse::Success { record }),
                asked_for,
            )
        };

        let accepted = reply(Bytes::from(ours.to_bytes()));
        assert_eq!(
            accepted
                .expect("a reply")
                .expect("valid")
                .expect("present")
                .state_id(),
            ours.state_id()
        );

        // Someone else's pointer: signed, genuine, and not what was asked for.
        assert!(reply(Bytes::from(theirs.to_bytes()))
            .expect("a reply")
            .is_err());

        // Tampering with any byte breaks the signature, so nothing parses.
        let mut tampered = ours.to_bytes();
        tampered[100] ^= 0xff;
        assert!(reply(Bytes::from(tampered)).expect("a reply").is_err());
        assert!(reply(Bytes::new()).expect("a reply").is_err());

        // "I do not have it" is an answer, and counts towards the quorum —
        // but only about the address that was asked for.
        assert!(read_get_reply(
            ChunkMessageBody::PointerGetResponse(PointerGetResponse::NotFound {
                address: asked_for
            }),
            asked_for,
        )
        .expect("a reply")
        .expect("valid")
        .is_none());
        assert!(read_get_reply(
            ChunkMessageBody::PointerGetResponse(PointerGetResponse::NotFound {
                address: [0u8; 32]
            }),
            asked_for,
        )
        .expect("a reply")
        .is_err());

        // A message that is not a reply to this request is not an answer at all.
        assert!(read_get_reply(
            ChunkMessageBody::PointerPutResponse(PointerPutResponse::Success {
                address: asked_for,
                state_id: ours.state_id(),
            }),
            asked_for,
        )
        .is_none());
    }

    /// A peer that answers with a record the client never sent must not end the
    /// write. Otherwise one peer takes the payment, stores nothing, and says
    /// "stored".
    #[test]
    fn an_acknowledgement_must_name_the_record_that_was_sent() {
        let (pk, sk) = keypair(9);
        let sent = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let other = Pointer::create(&sk, &pk, chunk_target(2)).expect("create");
        // Same address — same owner — but a different state.
        assert_eq!(sent.address(), other.address());
        assert_ne!(sent.state_id(), other.state_id());

        let judged = |response| {
            read_put_reply(
                ChunkMessageBody::PointerPutResponse(response),
                sent.address(),
                sent.state_id(),
            )
            .expect("a reply")
        };

        for honest in [
            PointerPutResponse::Success {
                address: sent.address(),
                state_id: sent.state_id(),
            },
            // A re-submission of a state the node already holds: the record is
            // stored, which is all the write asked for.
            PointerPutResponse::Unchanged {
                address: sent.address(),
                state_id: sent.state_id(),
            },
        ] {
            assert!(matches!(judged(honest), Ok(PutAck::Stored)));
        }

        for lie in [
            // The right address, some other state of the same pointer.
            PointerPutResponse::Success {
                address: sent.address(),
                state_id: other.state_id(),
            },
            // The right state, at an address that was never written.
            PointerPutResponse::Success {
                address: [0u8; 32],
                state_id: sent.state_id(),
            },
            PointerPutResponse::Unchanged {
                address: sent.address(),
                state_id: other.state_id(),
            },
            // Losing a race is not storing.
            PointerPutResponse::Stale {
                address: sent.address(),
                state_id: other.state_id(),
            },
            // Nor is a refusal about somebody else's pointer.
            PointerPutResponse::Stale {
                address: [0u8; 32],
                state_id: other.state_id(),
            },
            PointerPutResponse::PaymentRequired {
                message: "pay up".to_string(),
            },
        ] {
            assert!(
                !matches!(judged(lie), Ok(PutAck::Stored)),
                "this must not count as stored"
            );
        }
    }

    /// A lookup that comes back short does not shrink the quorums: they are
    /// counted over the configured group, so one returned peer can neither
    /// complete a write nor decide a read.
    #[test]
    fn a_short_lookup_is_a_shortfall_not_a_smaller_quorum() {
        let width = quorum_width(1, 7);
        assert_eq!(write_quorum(width), 5, "a write still needs five copies");
        assert_eq!(read_quorum(width), 4, "a read still needs four answers");
        assert_eq!(corroboration(width), 2, "and two peers naming its state");
        assert_eq!(quorum_width(9, 7), 9, "a wider lookup is counted as it is");
    }

    fn answered(count: usize, refusal: Option<Error>) -> Answered {
        let refusals = usize::from(refusal.is_some());
        Answered {
            count,
            last_error: None,
            refusal,
            refusals,
            busy: 0,
        }
    }

    /// One peer's word cannot throw a paid write away. Four peers stored it and
    /// one claims the pointer moved on: unless a read confirms that, the round
    /// is a shortfall, retried with the proof already paid for.
    #[test]
    fn one_peer_cannot_end_a_paid_write_that_others_stored() {
        let address = [7u8; 32];
        let refused = || Some(Error::Payment("pay up".to_string()));

        let unconfirmed = judge_write(&address, 4, 5, false, answered(5, None));
        assert!(
            matches!(&unconfirmed, Err(e) if worth_retrying(e)),
            "a claim nobody confirmed is a shortfall, got {unconfirmed:?}"
        );
        let refused_after_stores = judge_write(&address, 2, 5, false, answered(3, refused()));
        assert!(
            matches!(&refused_after_stores, Err(e) if worth_retrying(e)),
            "a refusal after others took the proof is retried, got {refused_after_stores:?}"
        );

        let confirmed = judge_write(&address, 4, 5, true, answered(5, None));
        assert!(
            matches!(&confirmed, Err(e) if !worth_retrying(e)),
            "a move a read confirmed is final, got {confirmed:?}"
        );
        assert!(
            matches!(
                judge_write(
                    &address,
                    0,
                    5,
                    false,
                    Answered {
                        refusals: 2,
                        ..answered(0, refused())
                    }
                ),
                Err(Error::Payment(_))
            ),
            "a refusal a second peer repeats, with nobody storing, is the answer"
        );
        assert!(judge_write(&address, 5, 5, false, answered(5, None)).is_ok());
    }

    /// Nor can one peer end it while the rest of the group is silent. Six
    /// peers time out and one refuses: that refusal is one peer's word, so
    /// the round is retried with the proof already paid for.
    #[test]
    fn one_refusal_among_silent_peers_is_retried() {
        let address = [7u8; 32];
        let alone = judge_write(
            &address,
            0,
            5,
            false,
            Answered {
                last_error: Some(Error::Timeout("no answer".to_string())),
                ..answered(0, Some(Error::Payment("pay up".to_string())))
            },
        );
        assert!(
            matches!(&alone, Err(e) if worth_retrying(e)),
            "one refusal among silent peers is a shortfall, got {alone:?}"
        );
    }

    /// Tally some replies and ask what the group's answer is.
    fn tally(replies: Vec<Option<Pointer>>) -> Replies {
        let mut seen = Replies::default();
        for reply in replies {
            seen.add(reply);
        }
        seen
    }

    /// Reads take the best answer, not the first: any single peer is entitled
    /// to serve a stale record, and must not be able to pin a reader to it.
    #[test]
    fn a_read_keeps_the_winner_whatever_order_replies_arrive_in() {
        let (pk, sk) = keypair(10);
        let old = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let new = old.update(&sk, chunk_target(2)).expect("update");
        let old = || Some(old.clone());
        let new = || Some(new.clone());

        for order in [
            vec![old(), old(), new(), new()],
            vec![new(), new(), old(), old()],
            vec![None, old(), new(), None, new(), old()],
            vec![new(), None, old(), new(), old()],
        ] {
            assert_eq!(
                tally(order).corroborated(2).expect("an answer").state_id(),
                new().expect("new").state_id(),
                "the newest corroborated state wins however the replies interleave"
            );
        }
        assert!(
            tally(vec![None, None]).corroborated(2).is_none(),
            "nobody holds it"
        );
        assert!(!tally(vec![None, None]).any(), "and nobody named a state");
    }

    /// One peer naming a higher state must not bury the state the rest of the
    /// group agrees on.
    ///
    /// Two ways to arrive here. A bad peer offers an owner-signed state nobody
    /// paid to store: it can no longer make the client return it, but if it
    /// could discard the count behind the real state it would make the pointer
    /// unreadable instead — a denial of service in place of a forgery. And an
    /// ordinary read taken while an update is in flight looks exactly the same.
    #[test]
    fn a_higher_state_only_one_peer_has_does_not_bury_the_agreed_one() {
        let (pk, sk) = keypair(12);
        let agreed = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let singleton = Pointer::sign(&sk, &pk, 900, chunk_target(9)).expect("sign");
        assert!(singleton.replaces(&agreed), "it does outrank what is held");

        let agreed_reply = || Some(agreed.clone());
        let singleton_reply = || Some(singleton.clone());

        for order in [
            vec![singleton_reply(), agreed_reply(), agreed_reply()],
            vec![agreed_reply(), singleton_reply(), agreed_reply()],
            vec![agreed_reply(), agreed_reply(), singleton_reply()],
            vec![
                singleton_reply(),
                None,
                agreed_reply(),
                agreed_reply(),
                agreed_reply(),
            ],
        ] {
            let seen = tally(order);
            assert_eq!(
                seen.corroborated(2).expect("an answer").state_id(),
                agreed.state_id(),
                "the state the group agrees on is the answer, whenever the \
                 singleton arrives"
            );
        }

        // And once a second peer confirms it, it is the answer — that is the
        // bar, and two colluding peers can clear it. See ADR-0016.
        let seen = tally(vec![
            singleton_reply(),
            singleton_reply(),
            agreed_reply(),
            agreed_reply(),
        ]);
        assert_eq!(
            seen.corroborated(2).expect("an answer").state_id(),
            singleton.state_id()
        );
    }

    /// Close-group peers 1 to 7 answering in turn, peer `n` after `10n`
    /// milliseconds: `Some(state)` is a peer's answer (`Some(None)`, it holds
    /// none), and `None` a peer that does not answer.
    fn in_turn(states: Vec<Option<Option<&Pointer>>>) -> Answers {
        (1u8..)
            .zip(states)
            .filter_map(|(n, state)| {
                let state = state?;
                Some((
                    n,
                    Duration::from_millis(10 * u64::from(n)),
                    Ok(state.cloned()),
                ))
            })
            .collect()
    }

    /// A write that reached five of seven peers must read back, even when one
    /// peer replays the older record it replaced.
    ///
    /// The two peers the write missed still hold the older state, honestly,
    /// and the replaying peer makes three. If those three answer first, the
    /// older state is corroborated after four answers while the newer one has
    /// been named once. Stopping there hands back the state the write replaced
    /// while four peers hold the new one, so the read keeps asking until the
    /// newer state is corroborated or the group is exhausted. A newer state
    /// nobody corroborates still never wins.
    ///
    /// The same holds when the bootstrap peers are asked beside the close
    /// group, here the close group and two more as on a small network: they
    /// settle on the older state, and the close group's newer one is the
    /// answer.
    #[tokio::test(start_paused = true)]
    async fn a_replayed_older_state_cannot_end_a_read_before_the_newer_one_is_heard() {
        let (pk, sk) = keypair(13);
        let old = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let new = old.update(&sk, chunk_target(2)).expect("update");
        let address = old.address();
        let (older, newer) = (Some(Some(&old)), Some(Some(&new)));
        // The three holding the older state answer first, at 10, 20 and 30
        // ms, then the four holding the newer, at 40 to 70 ms.
        let everyone = || in_turn(vec![older, older, older, newer, newer, newer, newer]);
        // Only the first of the four answers; the other three time out at
        // 10 s.
        let one_newer = || in_turn(vec![older, older, older, newer]);
        let seeds = || (1..=7).chain(101..=102);
        let with_seeds =
            |close_group: Answers| joined([close_group, answering(101..=102, 5, || Ok(None))]);

        // After four answers the older state is corroborated and the newer
        // named once, so the read goes on; the fifth answer, the second
        // naming the newer state, at 50 ms, settles it.
        let (found, took, _) =
            simulated_read(address, 0, 1..=7, std::iter::empty(), everyone()).await;
        assert_eq!(
            read_state_id(found),
            new.state_id(),
            "the state the write stored is the answer"
        );
        assert_eq!(took, Duration::from_millis(50));
        let (found, took, asked) =
            simulated_read(address, 0, 1..=7, seeds(), with_seeds(everyone())).await;
        assert_eq!(read_state_id(found), new.state_id());
        assert_eq!(took, Duration::from_millis(50));
        assert!(asked.values().all(|gets| *gets == 1), "{asked:?}");

        // When nobody else confirms the newer state, it is still one peer's
        // word, and the group's answer stands, once the rest of the group has
        // timed out.
        let (found, took, _) =
            simulated_read(address, 0, 1..=7, std::iter::empty(), one_newer()).await;
        assert_eq!(
            read_state_id(found),
            old.state_id(),
            "a newer state one peer names never wins"
        );
        assert_eq!(took, Duration::from_secs(10));
        let (found, took, _) =
            simulated_read(address, 0, 1..=7, seeds(), with_seeds(one_newer())).await;
        assert_eq!(read_state_id(found), old.state_id());
        assert_eq!(took, Duration::from_secs(10));
    }

    /// The fan-out both a write and a read use, driven with synthetic replies.
    ///
    /// A majority ends the operation. The peers that have not answered are
    /// dropped mid-flight, so one unreachable peer cannot hold the operation
    /// open for its whole timeout after the answer is already decided.
    #[tokio::test]
    async fn a_majority_ends_the_operation_and_a_dead_peer_cannot_stall_it() {
        let group = |good: usize, dead: usize| {
            let in_flight: FuturesUnordered<BoxFuture<'static, Result<Option<Pointer>>>> =
                FuturesUnordered::new();
            for _ in 0..good {
                in_flight.push(Box::pin(async { Ok(None) }));
            }
            for _ in 0..dead {
                in_flight.push(Box::pin(futures::future::pending()));
            }
            in_flight
        };

        // Four of seven answer; three never will. Without the early return this
        // would never finish.
        let answered = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ask_the_group(group(4, 3), read_quorum(7), |_| true),
        )
        .await
        .expect("a majority must end the read without waiting for the rest");
        assert_eq!(answered.count, 4);

        // One short of a majority, and the rest are gone: the caller is told
        // how many answered rather than being handed one peer's word.
        let answered = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ask_the_group(group(3, 0), read_quorum(7), |_| true),
        )
        .await
        .expect("nothing is in flight to wait for");
        assert_eq!(answered.count, 3, "three is not a majority of seven");
    }

    /// A peer that errors has not answered, and cannot make up a quorum.
    #[tokio::test]
    async fn an_error_is_not_an_answer() {
        let in_flight: FuturesUnordered<BoxFuture<'static, Result<Option<Pointer>>>> =
            FuturesUnordered::new();
        for _ in 0..6 {
            in_flight.push(Box::pin(async {
                Err(Error::Protocol("peer refused".to_string()))
            }));
        }
        in_flight.push(Box::pin(async { Ok(None) }));

        let answered = ask_the_group(in_flight, read_quorum(7), |_| true).await;
        assert_eq!(answered.count, 1, "six failures are not six answers");
        assert!(
            answered.failure().is_some(),
            "the failure must be kept to explain the shortfall"
        );
    }

    /// A refusal is kept apart from a missing answer, so a write that fell
    /// short because peers said no can report that rather than a timeout.
    #[tokio::test]
    async fn a_refusal_is_kept_apart_from_a_missing_answer() {
        let in_flight: FuturesUnordered<BoxFuture<'static, Result<()>>> = FuturesUnordered::new();
        in_flight.push(Box::pin(async { Err(Error::Timeout("slow".to_string())) }));
        in_flight.push(Box::pin(async {
            Err(Error::InvalidData(
                "the pointer moved while this update was in flight".to_string(),
            ))
        }));
        in_flight.push(Box::pin(async { Err(Error::Timeout("slow".to_string())) }));
        in_flight.push(Box::pin(async { Ok(()) }));

        let answered = ask_the_group(in_flight, write_quorum(7), |()| true).await;
        assert_eq!(answered.count, 1);
        assert_eq!(answered.refusals, 1);
        assert!(
            matches!(&answered.refusal, Some(Error::InvalidData(message)) if message.contains("moved")),
            "the refusal is what the write reports"
        );
        assert!(matches!(answered.last_error, Some(Error::Timeout(_))));
    }

    fn id(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    /// A peer that does not answer: its GET times out.
    fn silent() -> Result<Option<Pointer>> {
        Err(Error::Timeout("pointer GET timed out".to_string()))
    }

    /// The answers of a simulated network: what each peer says to a pointer
    /// GET, and how long it takes to say it.
    type Answers = Vec<(u8, Duration, Result<Option<Pointer>>)>;

    /// Several sets of answers as one.
    fn joined(parts: impl IntoIterator<Item = Answers>) -> Answers {
        parts.into_iter().flatten().collect()
    }

    /// Each of `peers` answering `reply()` after `after` milliseconds.
    fn answering(
        peers: impl IntoIterator<Item = u8>,
        after: u64,
        reply: impl Fn() -> Result<Option<Pointer>>,
    ) -> Answers {
        peers
            .into_iter()
            .map(|peer| (peer, Duration::from_millis(after), reply()))
            .collect()
    }

    /// A read as `pointer_get` makes one with the default close-group size,
    /// on a simulated network in paused time: the lookup returns `close_group`
    /// after `lookup` milliseconds, and each peer gives its answer from
    /// `answers`, or times out after ten seconds when it has none. Returns the
    /// read, how long it took, and how many GETs each peer was sent.
    async fn simulated_read(
        address: XorName,
        lookup: u64,
        close_group: impl IntoIterator<Item = u8>,
        bootstrap: impl IntoIterator<Item = u8>,
        answers: Answers,
    ) -> (
        Result<Option<Pointer>>,
        Duration,
        std::collections::HashMap<u8, usize>,
    ) {
        simulated_busy_read(address, lookup, close_group, bootstrap, answers, &[]).await
    }

    /// [`simulated_read`], with the peers in `busy` held off for having
    /// declined a session while busy.
    async fn simulated_busy_read(
        address: XorName,
        lookup: u64,
        close_group: impl IntoIterator<Item = u8>,
        bootstrap: impl IntoIterator<Item = u8>,
        answers: Answers,
        busy: &[u8],
    ) -> (
        Result<Option<Pointer>>,
        Duration,
        std::collections::HashMap<u8, usize>,
    ) {
        let close_group: Vec<(PeerId, Vec<MultiAddr>)> = close_group
            .into_iter()
            .map(|n| (id(n), Vec::new()))
            .collect();
        let bootstrap: Vec<(PeerId, Vec<MultiAddr>)> =
            bootstrap.into_iter().map(|n| (id(n), Vec::new())).collect();
        let answers = std::cell::RefCell::new(
            answers
                .into_iter()
                .map(|(n, after, reply)| (id(n), (after, reply)))
                .collect::<std::collections::HashMap<_, _>>(),
        );
        let asked = std::cell::RefCell::new(std::collections::HashMap::new());
        let started = tokio::time::Instant::now();
        let read = read_pointer(
            &address,
            async move {
                tokio::time::sleep(Duration::from_millis(lookup)).await;
                Ok::<_, Error>(close_group)
            },
            ant_protocol::CLOSE_GROUP_SIZE,
            &bootstrap,
            |peer, _| {
                *asked.borrow_mut().entry(peer.as_bytes()[0]).or_insert(0) += 1;
                let (after, reply) = answers
                    .borrow_mut()
                    .remove(&peer)
                    .unwrap_or_else(|| (Duration::from_secs(10), silent()));
                async move {
                    tokio::time::sleep(after).await;
                    reply
                }
            },
            |peer| busy.contains(&peer.as_bytes()[0]),
        )
        .await;
        (read, started.elapsed(), asked.into_inner())
    }

    fn read_state_id(read: Result<Option<Pointer>>) -> XorName {
        read.expect("a read").expect("a state").state_id()
    }

    /// A pointer read most of whose close group is held off for having
    /// declined a session while busy says the nodes are busy, in the words a
    /// chunk read uses, rather than that too few answered; with the bootstrap
    /// peers asked beside it too. Busy peers that are not needed for the
    /// quorum change nothing, and a shortfall with no busy peer is still a
    /// shortfall.
    #[tokio::test(start_paused = true)]
    async fn busy_holders_make_a_pointer_read_busy_not_short() {
        let address = [9u8; 32];
        let busy_failure = || {
            Err(Error::Network(
                "pointer GET send failed: refused".to_string(),
            ))
        };
        // Three of seven answer that they hold nothing; four fail at once.
        let answers = || {
            joined([
                answering(1..=3, 5, || Ok(None)),
                answering(4..=7, 1, busy_failure),
            ])
        };
        let busy = [4, 5, 6, 7];
        let is_busy = |found: &Result<Option<Pointer>>| {
            matches!(found, Err(Error::Network(message))
                if message.contains("are busy; try again shortly")
                    && message.contains(&hex::encode(address)))
        };

        let (found, _, _) =
            simulated_busy_read(address, 0, 1..=7, std::iter::empty(), answers(), &busy).await;
        assert!(is_busy(&found), "{found:?}");
        let (found, _, _) = simulated_busy_read(
            address,
            0,
            1..=7,
            101..=102,
            joined([answers(), answering(101..=102, 5, || Ok(None))]),
            &busy,
        )
        .await;
        assert!(is_busy(&found), "{found:?}");

        // The same failures from peers not held off: a shortfall.
        let (found, _, _) = simulated_read(address, 0, 1..=7, std::iter::empty(), answers()).await;
        assert!(
            matches!(found, Err(Error::CloseGroupShortfall(_))),
            "{found:?}"
        );

        // Four answer, a quorum of seven: one busy peer is no failure.
        let answers = joined([
            answering(1..=4, 5, || Ok(None)),
            answering(5..=7, 1, busy_failure),
        ]);
        let (found, _, _) =
            simulated_busy_read(address, 0, 1..=7, std::iter::empty(), answers, &[5]).await;
        assert!(matches!(found, Ok(None)), "{found:?}");
    }

    /// The browser's refusal hold-off.
    const HOLD_OFF: Duration = Duration::from_secs(15);

    /// The peer `n` steps from `address`: it differs from the address in its
    /// last byte alone, by `n`, so a lower `n` is nearer.
    fn near(address: &XorName, n: u8) -> PeerId {
        let mut bytes = *address;
        bytes[31] ^= n;
        PeerId::from_bytes(bytes)
    }

    /// A network in paused time on which peers 1 to 20 ([`near`] `address`)
    /// answer a pointer GET after 50 ms (or the delay [`Self::answering_after`]
    /// gives them) with the state `holds` gives them, or none, and those in
    /// `held_off` are held off as busy from the start, for the browser's
    /// hold-off or for good. Peers [`Self::declining`] names decline the first
    /// GET they are sent as busy, and are held off for the browser's hold-off
    /// from then. A lookup returns the seven nearest not held off, as a
    /// browser's lookup leaves held-off peers out.
    struct HeldOffNetwork {
        address: XorName,
        holds: HashMap<u8, Pointer>,
        held_off: Vec<u8>,
        /// When the hold-off ends; `None` when it never does.
        until: Option<tokio::time::Instant>,
        lookups: std::cell::Cell<usize>,
        /// Peers that decline the first GET they are sent as busy.
        declines: Vec<u8>,
        /// When the hold-off of each peer that declined ends.
        declined: std::cell::RefCell<HashMap<u8, tokio::time::Instant>>,
        /// Reply delays other than 50 ms.
        delays: HashMap<u8, Duration>,
    }

    impl HeldOffNetwork {
        fn new(
            address: XorName,
            holds: impl IntoIterator<Item = (u8, Pointer)>,
            held_off: impl IntoIterator<Item = u8>,
            for_good: bool,
        ) -> Self {
            Self {
                address,
                holds: holds.into_iter().collect(),
                held_off: held_off.into_iter().collect(),
                until: (!for_good).then(|| tokio::time::Instant::now() + HOLD_OFF),
                lookups: std::cell::Cell::new(0),
                declines: Vec::new(),
                declined: std::cell::RefCell::new(HashMap::new()),
                delays: HashMap::new(),
            }
        }

        /// `peers` decline the first GET they are sent as busy.
        fn declining(mut self, peers: impl IntoIterator<Item = u8>) -> Self {
            self.declines.extend(peers);
            self
        }

        /// `peers` answer after `delay` rather than 50 ms.
        fn answering_after(mut self, peers: impl IntoIterator<Item = u8>, delay: Duration) -> Self {
            self.delays.extend(peers.into_iter().map(|n| (n, delay)));
            self
        }

        /// The peers held off now, with the time until each is tried again.
        fn refused(&self) -> Vec<(PeerId, Duration)> {
            let now = tokio::time::Instant::now();
            let remaining = match self.until {
                Some(until) => until
                    .checked_duration_since(now)
                    .filter(|remaining| !remaining.is_zero()),
                None => Some(HOLD_OFF),
            };
            let mut refused: Vec<(PeerId, Duration)> =
                remaining.map_or_else(Vec::new, |remaining| {
                    self.held_off
                        .iter()
                        .map(|n| (near(&self.address, *n), remaining))
                        .collect()
                });
            refused.extend(self.declined.borrow().iter().filter_map(|(n, until)| {
                until
                    .checked_duration_since(now)
                    .filter(|remaining| !remaining.is_zero())
                    .map(|remaining| (near(&self.address, *n), remaining))
            }));
            refused
        }

        fn is_refused(&self, peer: &PeerId) -> bool {
            self.refused().iter().any(|(refused, _)| refused == peer)
        }

        fn held_off_now(&self) -> Vec<PeerId> {
            self.refused().into_iter().map(|(peer, _)| peer).collect()
        }

        async fn lookup(&self) -> Result<Vec<(PeerId, Vec<MultiAddr>)>> {
            self.lookups.set(self.lookups.get() + 1);
            Ok((1..=20)
                .map(|n| near(&self.address, n))
                .filter(|peer| !self.is_refused(peer))
                .take(ant_protocol::CLOSE_GROUP_SIZE)
                .map(|peer| (peer, Vec::new()))
                .collect())
        }

        async fn get(&self, peer: PeerId) -> Result<Option<Pointer>> {
            let n = peer.as_bytes()[31] ^ self.address[31];
            let delay = self
                .delays
                .get(&n)
                .copied()
                .unwrap_or(Duration::from_millis(50));
            tokio::time::sleep(delay).await;
            if self.declines.contains(&n) && !self.declined.borrow().contains_key(&n) {
                self.declined
                    .borrow_mut()
                    .insert(n, tokio::time::Instant::now() + HOLD_OFF);
                return Err(Error::Network(format!("peer {n} declined: busy")));
            }
            Ok(self.holds.get(&n).cloned())
        }

        /// A read as `pointer_get` makes one, with no bootstrap peer.
        async fn read(&self) -> Result<Option<Pointer>> {
            past_refusals(
                &self.address,
                ant_protocol::CLOSE_GROUP_SIZE,
                || self.refused(),
                read_is_open,
                || async move {
                    let held_off = self.held_off_now();
                    let read = read_pointer_with_seeds(
                        &self.address,
                        self.lookup(),
                        ant_protocol::CLOSE_GROUP_SIZE,
                        &[],
                        |peer, _| self.get(peer),
                        |peer| self.is_refused(peer),
                        &held_off,
                    )
                    .await;
                    (read.found, read.contacted)
                },
            )
            .await
        }

        /// A finality check as `pointer_finality` makes one, with no
        /// bootstrap peer.
        async fn finality(&self) -> Result<PointerFinality> {
            past_refusals(
                &self.address,
                ant_protocol::CLOSE_GROUP_SIZE,
                || self.refused(),
                finality_is_open,
                || async move {
                    let held_off = self.held_off_now();
                    pointer_finality_from(
                        &self.address,
                        || self.lookup(),
                        ant_protocol::CLOSE_GROUP_SIZE,
                        &[],
                        |peer, _| self.get(peer),
                        |peer| self.is_refused(peer),
                        &held_off,
                    )
                    .await
                },
            )
            .await
        }

        /// A census as `close_group_finality` takes one, before an update or
        /// a transfer pays.
        async fn census(&self) -> Result<PointerFinality> {
            past_refusals(
                &self.address,
                ant_protocol::CLOSE_GROUP_SIZE,
                || self.refused(),
                finality_is_open,
                || async move {
                    let held_off = self.held_off_now();
                    let (census, contacted) = close_group_census(
                        &self.address,
                        self.lookup(),
                        ant_protocol::CLOSE_GROUP_SIZE,
                        |peer, _| self.get(peer),
                        &held_off,
                    )
                    .await;
                    (census.map(|(finality, _)| finality), contacted)
                },
            )
            .await
        }
    }

    /// The whole close group is held off as busy, so the lookup leaves it out
    /// and seven farther peers answer that they hold nothing: a read quorum
    /// of seven. The pointer is not reported absent, nor open with no state:
    /// the read is made again once the hold-off ends, and finds the state.
    #[tokio::test(start_paused = true)]
    async fn a_held_off_close_group_is_read_after_its_hold_off_rather_than_reported_absent() {
        let (pk, sk) = keypair(60);
        let held = Pointer::create(&sk, &pk, chunk_target(1))
            .expect("create")
            .update(&sk, chunk_target(2))
            .expect("update");
        let holds = || (1..=7).map(|n| (n, held.clone()));

        let start = tokio::time::Instant::now();
        let network = HeldOffNetwork::new(held.address(), holds(), 1..=7, false);
        let read = network.read().await;
        assert_eq!(read_state_id(read), held.state_id());
        assert_eq!(network.lookups.get(), 2);
        assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(50));

        // The finality check, census and read alike.
        let start = tokio::time::Instant::now();
        let network = HeldOffNetwork::new(held.address(), holds(), 1..=7, false);
        let finality = network.finality().await.expect("a check");
        assert_eq!(finality.status, FinalityStatus::Open { counter: Some(1) });
        assert_eq!((finality.group, finality.answered), (7, 7));
        assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(100));
    }

    /// The five peers of the close group holding the newest state, a write
    /// quorum, are held off as busy, and the two holding an older one are
    /// not. Corroborated by those two at a read quorum, the older state is
    /// not the answer: the read is made again once the hold-off ends, and
    /// finds the newer.
    #[tokio::test(start_paused = true)]
    async fn a_held_off_write_quorum_is_read_after_its_hold_off_rather_than_an_older_state() {
        let (pk, sk) = keypair(61);
        let older = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let newer = older.update(&sk, chunk_target(2)).expect("update");
        let holds = || {
            (1..=5)
                .map(|n| (n, newer.clone()))
                .chain((6..=7).map(|n| (n, older.clone())))
        };

        let start = tokio::time::Instant::now();
        let network = HeldOffNetwork::new(older.address(), holds(), 1..=5, false);
        let read = network.read().await;
        assert_eq!(read_state_id(read), newer.state_id());
        assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(50));

        let network = HeldOffNetwork::new(older.address(), holds(), 1..=5, false);
        let finality = network.finality().await.expect("a check");
        assert_eq!(finality.status, FinalityStatus::Open { counter: Some(1) });
    }

    /// A close group held off for good: the read waits out the hold-off
    /// three times, then says the nodes are busy rather than that the
    /// pointer is absent.
    #[tokio::test(start_paused = true)]
    async fn a_close_group_held_off_for_good_makes_a_pointer_read_busy_not_absent() {
        let (pk, sk) = keypair(62);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let start = tokio::time::Instant::now();
        let network = HeldOffNetwork::new(
            held.address(),
            (1..=7).map(|n| (n, held.clone())),
            1..=7,
            true,
        );
        let read = network.read().await;
        assert!(
            matches!(&read, Err(Error::Network(message))
                if message.contains("are busy; try again shortly")),
            "{read:?}"
        );
        let waits = crate::client_engine::read::MAX_REFUSAL_WAITS;
        assert_eq!(network.lookups.get(), waits + 1);
        assert_eq!(
            start.elapsed(),
            HOLD_OFF * u32::try_from(waits).unwrap()
                + Duration::from_millis(50) * u32::try_from(waits + 1).unwrap()
        );
    }

    /// One peer of the close group held off for good: the rest of the group
    /// is read to the end, a read quorum of it answers, and its answer, a
    /// state or none, stands with no wait.
    #[tokio::test(start_paused = true)]
    async fn one_held_off_peer_of_the_close_group_does_not_hold_up_a_pointer_read() {
        let (pk, sk) = keypair(63);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        for holds in [
            (1..=7).map(|n| (n, held.clone())).collect::<Vec<_>>(),
            vec![],
        ] {
            let found = !holds.is_empty();
            let start = tokio::time::Instant::now();
            let network = HeldOffNetwork::new(held.address(), holds, [3], true);
            let read = network.read().await.expect("a read");
            assert_eq!(
                read.map(|state| state.state_id()),
                found.then(|| held.state_id())
            );
            assert_eq!(network.lookups.get(), 1);
            assert_eq!(start.elapsed(), Duration::from_millis(50));
        }
    }

    /// Six of the close group are held off as busy, so the lookup asks the
    /// seventh and six farther peers. Only the seventh names the state, short
    /// of the two that corroborate one; or the one of two not held off names
    /// the newest state and the other an older one, neither by two. The
    /// shortfall is one the held-off peers explain: the read, and the
    /// finality check, are made again once the hold-off ends, and find the
    /// newest state.
    #[tokio::test(start_paused = true)]
    async fn a_shortfall_held_off_peers_explain_is_read_again_after_their_hold_off() {
        let (pk, sk) = keypair(64);
        let older = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let newer = older.update(&sk, chunk_target(2)).expect("update");
        let cases = [
            (
                (1..=7).map(|n| (n, newer.clone())).collect::<Vec<_>>(),
                (1..=6).collect::<Vec<u8>>(),
            ),
            (
                (1..=6)
                    .map(|n| (n, newer.clone()))
                    .chain([(7, older.clone())])
                    .collect(),
                (1..=5).collect(),
            ),
        ];
        for (holds, held_off) in cases {
            let start = tokio::time::Instant::now();
            let network =
                HeldOffNetwork::new(newer.address(), holds.clone(), held_off.clone(), false);
            let read = network.read().await;
            assert_eq!(read_state_id(read), newer.state_id());
            assert_eq!(network.lookups.get(), 2);
            assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(50));

            let start = tokio::time::Instant::now();
            let network = HeldOffNetwork::new(newer.address(), holds, held_off, false);
            let finality = network.finality().await.expect("a check");
            assert_eq!(finality.status, FinalityStatus::Open { counter: Some(1) });
            assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(100));
        }
    }

    /// Four of the close group decline the read as busy during the round,
    /// and are held off from then: the three that answer are short of a read
    /// quorum. That is not the answer, nor is "busy" at once: the read, the
    /// census and the finality check wait out the hold-off, as a chunk read
    /// does, and find the state.
    #[tokio::test(start_paused = true)]
    async fn a_close_group_that_declines_as_busy_during_the_round_is_read_after_its_hold_off() {
        let (pk, sk) = keypair(65);
        let held = Pointer::create(&sk, &pk, chunk_target(1))
            .expect("create")
            .update(&sk, chunk_target(2))
            .expect("update");
        let network = || {
            HeldOffNetwork::new(
                held.address(),
                (1..=7).map(|n| (n, held.clone())),
                [],
                false,
            )
            .declining(1..=4)
        };

        let start = tokio::time::Instant::now();
        let read_network = network();
        let read = read_network.read().await;
        assert_eq!(read_state_id(read), held.state_id());
        assert_eq!(read_network.lookups.get(), 2);
        assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(100));

        let start = tokio::time::Instant::now();
        let census = network().census().await.expect("a census");
        assert_eq!(census.status, FinalityStatus::Open { counter: Some(1) });
        assert_eq!((census.group, census.answered), (7, 7));
        assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(100));

        let start = tokio::time::Instant::now();
        let finality = network().finality().await.expect("a check");
        assert_eq!(finality.status, FinalityStatus::Open { counter: Some(1) });
        assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(150));
    }

    /// The census an update or a transfer takes before paying, of a close
    /// group held off as busy: seven farther peers answer that they hold
    /// nothing, and the census is taken again once the hold-off ends, and
    /// finds the state, rather than reporting the pointer open with none.
    #[tokio::test(start_paused = true)]
    async fn a_census_of_a_held_off_close_group_is_taken_after_its_hold_off() {
        let (pk, sk) = keypair(66);
        let held = Pointer::create(&sk, &pk, chunk_target(1))
            .expect("create")
            .update(&sk, chunk_target(2))
            .expect("update");
        let start = tokio::time::Instant::now();
        let network = HeldOffNetwork::new(
            held.address(),
            (1..=7).map(|n| (n, held.clone())),
            1..=7,
            false,
        );
        let census = network.census().await.expect("a census");
        assert_eq!(census.status, FinalityStatus::Open { counter: Some(1) });
        assert_eq!((census.group, census.answered), (7, 7));
        assert_eq!(network.lookups.get(), 2);
        assert_eq!(start.elapsed(), HOLD_OFF + Duration::from_millis(50));
    }

    /// The nearest peer of the close group is held off as busy and holds a
    /// rival final state; the six others and the farther peer the lookup
    /// asks in its place hold the majority one. Seven of seven asked answer,
    /// but a member of the true group was not asked, so the state is
    /// unconfirmed, not final, in the census and the finality check alike. A
    /// peer held off outside the group leaves it final.
    #[tokio::test(start_paused = true)]
    async fn a_final_state_is_unconfirmed_while_a_held_off_group_member_was_not_asked() {
        let (pk, sk) = keypair(67);
        let created = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let majority = created.finalize(&sk, chunk_target(5)).expect("finalize");
        let rival = created.finalize(&sk, chunk_target(6)).expect("finalize");
        let holds = || {
            [(1, rival.clone())]
                .into_iter()
                .chain((2..=8).map(|n| (n, majority.clone())))
        };
        let network = HeldOffNetwork::new(majority.address(), holds(), [1], true);
        for finality in [
            network.census().await.expect("a census"),
            network.finality().await.expect("a check"),
        ] {
            assert_eq!((finality.group, finality.answered), (7, 7));
            match finality.status {
                FinalityStatus::Unconfirmed(state) => {
                    assert_eq!(state.state_id, majority.state_id());
                    assert_eq!(state.holders, 7);
                }
                other => panic!("expected Unconfirmed, got {other:?}"),
            }
        }

        let holds = (1..=9).map(|n| (n, majority.clone()));
        let network = HeldOffNetwork::new(majority.address(), holds, [9], true);
        let finality = network.census().await.expect("a census");
        assert!(
            matches!(&finality.status, FinalityStatus::Final(state)
                if state.state_id == majority.state_id()),
            "{finality:?}"
        );
    }

    /// One peer of the close group is held off for good and the farther peer
    /// the lookup asks in its place answers first. A read that settled on the
    /// first four answers would count three of the true group and wait out
    /// the hold-off; the group is read to the end instead, six of the true
    /// group answer, and the read and the finality check stand with no wait.
    #[tokio::test(start_paused = true)]
    async fn a_held_off_group_member_has_the_rest_of_the_group_read_to_the_end() {
        let (pk, sk) = keypair(68);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let network = || {
            HeldOffNetwork::new(
                held.address(),
                (1..=8).map(|n| (n, held.clone())),
                [1],
                true,
            )
            .answering_after([8], Duration::from_millis(10))
        };

        let start = tokio::time::Instant::now();
        let read_network = network();
        let read = read_network.read().await;
        assert_eq!(read_state_id(read), held.state_id());
        assert_eq!(read_network.lookups.get(), 1);
        assert_eq!(start.elapsed(), Duration::from_millis(50));

        let start = tokio::time::Instant::now();
        let finality = network().finality().await.expect("a check");
        assert_eq!(finality.status, FinalityStatus::Open { counter: Some(0) });
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    /// A state the bootstrap peers corroborate is the answer when the close
    /// group gives none: it does not answer, too few of it answer, or it holds
    /// none.
    #[tokio::test(start_paused = true)]
    async fn a_state_the_bootstrap_peers_hold_is_read_when_the_close_group_has_none() {
        let (pk, sk) = keypair(13);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        for close_group in [
            vec![],
            answering(1..=7, 50, || Ok(None)),
            answering(1..=3, 50, || Ok(None)),
        ] {
            let mut answers = close_group;
            answers.extend(answering(101..=102, 100, || Ok(Some(held.clone()))));
            answers.extend(answering([103], 100, || Ok(None)));
            let (read, _, _) = simulated_read(held.address(), 0, 1..=7, 101..=103, answers).await;
            assert_eq!(read_state_id(read), held.state_id());
        }
    }

    /// Both sets answer: the newer corroborated state is the answer, whichever
    /// set names it, so an older state from one cannot roll back the other's.
    #[tokio::test(start_paused = true)]
    async fn the_newer_state_wins_whichever_set_names_it() {
        let (pk, sk) = keypair(14);
        let old = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let new = old.update(&sk, chunk_target(2)).expect("update");
        for (close_group, bootstrap) in [(&new, &old), (&old, &new)] {
            let mut answers = answering(1..=7, 50, || Ok(Some(close_group.clone())));
            answers.extend(answering(101..=109, 100, || Ok(Some(bootstrap.clone()))));
            let (read, _, _) = simulated_read(old.address(), 0, 1..=7, 101..=109, answers).await;
            assert_eq!(read_state_id(read), new.state_id());
        }
        // Agreement is per set: a newer state only one bootstrap peer names
        // does not replace the close group's.
        let mut answers = answering(1..=7, 50, || Ok(Some(old.clone())));
        answers.extend(answering(101..=108, 100, || Ok(None)));
        answers.extend(answering([109], 100, || Ok(Some(new.clone()))));
        let (read, _, _) = simulated_read(old.address(), 0, 1..=7, 101..=109, answers).await;
        assert_eq!(read_state_id(read), old.state_id());
    }

    /// Whether a pointer exists, and why a read failed, are the close group's
    /// to report: the bootstrap peers holding none, failing, or naming a state
    /// only one of them holds changes nothing.
    #[tokio::test(start_paused = true)]
    async fn absence_and_failure_are_the_close_groups_to_report() {
        let (pk, sk) = keypair(15);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let address = held.address();
        let none = |peers: std::ops::RangeInclusive<u8>| answering(peers, 50, || Ok(None));
        let read = |answers| simulated_read(address, 0, 1..=7, 101..=109, answers);

        let (found, _, _) = read(joined([none(1..=7), none(101..=109)])).await;
        assert!(found.expect("a read").is_none());
        let (found, _, _) = read(none(101..=109)).await;
        assert!(matches!(found, Err(Error::Timeout(_))), "{found:?}");
        let (found, _, _) = read(joined([none(1..=3), none(101..=109)])).await;
        assert!(
            matches!(&found, Err(Error::CloseGroupShortfall(message))
                if message.starts_with("only 3 of the close group answered")),
            "{found:?}"
        );
        let mut lone = none(1..=7);
        lone.extend(none(102..=109));
        lone.extend(answering([101], 50, || Ok(Some(held.clone()))));
        let (found, _, _) = read(lone).await;
        assert!(found.expect("a read").is_none());
        let (found, _, _) = read(answering(1..=7, 50, || Ok(Some(held.clone())))).await;
        assert_eq!(read_state_id(found), held.state_id());
    }

    /// With no state from the bootstrap peers, the close group's outcome is
    /// returned exactly as it was.
    #[test]
    fn the_close_groups_outcome_stands_without_a_bootstrap_state() {
        let (pk, sk) = keypair(16);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let outcomes = || -> Vec<Result<Option<Pointer>>> {
            vec![
                Ok(None),
                Ok(Some(held.clone())),
                Err(Error::CloseGroupShortfall(
                    "only 3 of the close group answered".into(),
                )),
            ]
        };
        for bootstrap_failed in [false, true] {
            for (close_group, expected) in outcomes().into_iter().zip(outcomes()) {
                let seen = close_group.as_ref().ok().cloned().flatten();
                let close_group = SetRead {
                    outcome: close_group,
                    seen,
                };
                let bootstrap = SetRead {
                    outcome: if bootstrap_failed { silent() } else { Ok(None) },
                    seen: None,
                };
                match (newest_pointer(close_group, bootstrap), expected) {
                    (Ok(read), Ok(expected)) => assert_eq!(
                        read.map(|state| state.state_id()),
                        expected.map(|state| state.state_id())
                    ),
                    (Err(read), Err(expected)) => {
                        assert_eq!(read.to_string(), expected.to_string())
                    }
                    (read, expected) => panic!("read {read:?}, expected {expected:?}"),
                }
            }
        }
    }

    /// A set too few of whose peers answered still keeps the other from
    /// rolling it back: the read fails with that set's shortfall rather than
    /// return an older state, or none, than its answers corroborate.
    #[tokio::test(start_paused = true)]
    async fn a_set_that_falls_short_still_keeps_its_newer_state_from_being_rolled_back() {
        let (pk, sk) = keypair(17);
        let old = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let new = old.update(&sk, chunk_target(2)).expect("update");
        let naming = |state: &Pointer, peers| answering(peers, 50, || Ok(Some(state.clone())));
        let read = |answers| simulated_read(old.address(), 0, 1..=7, 101..=109, answers);
        let shortfall = |found: &Result<Option<Pointer>>, of: &str| {
            matches!(found, Err(Error::CloseGroupShortfall(message))
                if message.starts_with(&format!("only 2 of {of} answered")))
        };

        // Two of the close group name the newer state, and the rest do not
        // answer: the bootstrap peers' older state is not the answer.
        let (found, _, _) = read(joined([naming(&new, 1..=2), naming(&old, 101..=109)])).await;
        assert!(shortfall(&found, "the close group"), "{found:?}");
        // Two bootstrap peers name the newer state, and the rest do not answer:
        // neither the close group's older state nor its absence is.
        let (found, _, _) = read(joined([naming(&old, 1..=7), naming(&new, 101..=102)])).await;
        assert!(shortfall(&found, "the bootstrap peers"), "{found:?}");
        let mut answers = answering(1..=7, 50, || Ok(None));
        answers.extend(naming(&new, 101..=102));
        let (found, _, _) = read(answers).await;
        assert!(shortfall(&found, "the bootstrap peers"), "{found:?}");
        // What a short set corroborates only ever holds back older states.
        let (found, _, _) = read(joined([naming(&old, 1..=2), naming(&new, 101..=109)])).await;
        assert_eq!(read_state_id(found), new.state_id());
    }

    /// The bootstrap peers are asked while the close group is looked up, not
    /// after it, and a close group that answers "none" first still waits for
    /// the state they name.
    #[tokio::test(start_paused = true)]
    async fn both_sets_are_read_at_once_and_both_are_waited_for() {
        let (pk, sk) = keypair(18);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let holders = || answering(101..=102, 100, || Ok(Some(held.clone())));
        // A slow lookup: the bootstrap peers have answered long before it ends.
        let (found, took, _) = simulated_read(
            held.address(),
            1000,
            1..=7,
            101..=102,
            joined([answering(1..=7, 50, || Ok(None)), holders()]),
        )
        .await;
        assert_eq!(read_state_id(found), held.state_id());
        assert_eq!(took, Duration::from_millis(1050));
        // The close group answers "none" at once; the bootstrap peers later.
        let late = answering(101..=102, 500, || Ok(Some(held.clone())));
        let (found, took, _) = simulated_read(
            held.address(),
            0,
            1..=7,
            101..=102,
            joined([answering(1..=7, 50, || Ok(None)), late]),
        )
        .await;
        assert_eq!(read_state_id(found), held.state_id());
        assert_eq!(took, Duration::from_millis(500));
    }

    /// When the close group holds none, the bootstrap peers are asked until
    /// every one has answered, so a state only two of the nine hold is found
    /// even when five others, a quorum, answer first. An absent pointer is
    /// reported only then: one bootstrap peer that does not answer holds it up
    /// for its GET timeout.
    #[tokio::test(start_paused = true)]
    async fn a_state_few_bootstrap_peers_hold_is_found_when_the_close_group_has_none() {
        let (pk, sk) = keypair(19);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let mut answers = answering(1..=7, 50, || Ok(None));
        answers.extend(answering(101..=105, 50, || Ok(None)));
        answers.extend(answering(106..=107, 300, || Ok(Some(held.clone()))));
        answers.extend(answering(108..=109, 400, || Ok(None)));
        let (found, took, _) = simulated_read(held.address(), 0, 1..=7, 101..=109, answers).await;
        assert_eq!(read_state_id(found), held.state_id());
        assert_eq!(took, Duration::from_millis(300));

        let mut answers = answering(1..=7, 50, || Ok(None));
        answers.extend(answering(101..=108, 50, || Ok(None)));
        let (found, took, _) = simulated_read(held.address(), 0, 1..=7, 101..=109, answers).await;
        assert!(found.expect("a read").is_none());
        assert_eq!(took, Duration::from_secs(10));
    }

    /// Nine bootstrap peers, the most a read is given, need five answers, and
    /// two of them naming a state, for the set to return it.
    #[tokio::test(start_paused = true)]
    async fn nine_bootstrap_peers_read_on_five_answers_with_two_naming_the_state() {
        let nine = crate::data::network::MAX_BOOTSTRAP_READ_PEERS;
        assert_eq!((read_quorum(nine), corroboration(nine)), (5, 2));
        let (pk, sk) = keypair(24);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let none = |peers: std::ops::RangeInclusive<u8>| answering(peers, 50, || Ok(None));
        let holding =
            |peers: std::ops::RangeInclusive<u8>| answering(peers, 100, || Ok(Some(held.clone())));
        let read = |answers| simulated_read(held.address(), 0, 1..=7, 101..=109, answers);

        // The close group holds none. Two bootstrap peers name the state and
        // three hold none: five answers, and the state is the read's.
        let (found, took, _) =
            read(joined([none(1..=7), holding(101..=102), none(103..=105)])).await;
        assert_eq!(read_state_id(found), held.state_id());
        assert_eq!(took, Duration::from_millis(100));
        // Two name it and two hold none: four answers are too few, and the
        // read fails rather than report the pointer absent.
        let (found, took, _) =
            read(joined([none(1..=7), holding(101..=102), none(103..=104)])).await;
        assert!(
            matches!(&found, Err(Error::CloseGroupShortfall(message))
                if message.starts_with("only 4 of the bootstrap peers answered")),
            "{found:?}"
        );
        assert_eq!(took, Duration::from_secs(10));
        // One names it and the other eight hold none: absent.
        let (found, _, _) = read(joined([none(1..=7), holding(101..=101), none(102..=109)])).await;
        assert!(found.expect("a read").is_none());
    }

    /// `pointer_get` and `pointer_finality` give a read the bootstrap peers
    /// their lookup leaves among the nine nearest the pointer, and all of the
    /// nine nearest when the lookup failed.
    #[test]
    fn a_pointer_read_asks_the_seeds_its_lookup_leaves_among_the_nine_nearest() {
        let id = |n: u8| PeerId::from_bytes([n; 32]);
        let seeds: Vec<(PeerId, Vec<MultiAddr>)> =
            (101..=109).map(|n| (id(n), Vec::new())).collect();
        let group: Vec<(PeerId, Vec<MultiAddr>)> = (1..=7).map(|n| (id(n), Vec::new())).collect();
        let asked = |group: Option<&[(PeerId, Vec<MultiAddr>)]>| {
            seeds_beside(group, seeds.clone(), &[0; 32])
                .into_iter()
                .map(|(peer, _)| peer.as_bytes()[0])
                .collect::<Vec<u8>>()
        };
        // Seven peers nearer than every seed: the two nearest seeds complete
        // the nine nearest, and only they are asked.
        assert_eq!(asked(Some(&group)), vec![101, 102]);
        // Nine peers nearer than every seed: the floor of two still asks the
        // two nearest seeds, so two can corroborate a state.
        let nine: Vec<(PeerId, Vec<MultiAddr>)> = (1..=9).map(|n| (id(n), Vec::new())).collect();
        assert_eq!(asked(Some(&nine)), vec![101, 102]);
        // Eight nearer: the nearest seed passes the filter and the floor adds
        // the next one.
        assert_eq!(asked(Some(&nine[..8])), vec![101, 102]);
        assert_eq!(crate::data::network::MIN_POINTER_READ_SEEDS, 2);
        // A thin lookup leaves more of them among the nearest.
        assert_eq!(asked(Some(&group[..2])), (101..=107).collect::<Vec<u8>>());
        // No lookup, or an empty one: all nine.
        assert_eq!(asked(None), (101..=109).collect::<Vec<u8>>());
        assert_eq!(asked(Some(&[])), (101..=109).collect::<Vec<u8>>());
    }

    /// A read given the bootstrap peers `bootstrap_read_peers` chooses from
    /// sixteen seeds, the most `pointer_get` gives one, asks the nine nearest the pointer
    /// and never the seven farther ones: two of the nine naming the state are
    /// enough on five answers, and a state only the farther seeds hold is not
    /// looked for there.
    #[tokio::test(start_paused = true)]
    async fn a_pointer_read_asks_the_nine_bootstrap_peers_nearest_the_pointer() {
        let (pk, sk) = keypair(25);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let address = held.address();
        // Sixteen seeds, 101 to 116, the highest listed first.
        let seeds: Vec<MultiAddr> = (101..=116u8)
            .rev()
            .map(|n| {
                format!(
                    "/ip4/127.0.0.1/udp/{}/quic/p2p/{}",
                    10_000 + u16::from(n),
                    hex::encode([n; 32])
                )
                .parse()
                .expect("a seed address")
            })
            .collect();
        let bootstrap: Vec<u8> = crate::data::network::bootstrap_read_peers(
            &seeds,
            &address,
            &PeerId::from_bytes([0xff; 32]),
        )
        .into_iter()
        .map(|(peer, _)| peer.as_bytes()[0])
        .collect();
        let mut nearest: Vec<u8> = (101..=116).collect();
        nearest.sort_by_key(|&n| ant_protocol::transport::xor_distance(&[n; 32], &address));
        assert_eq!(bootstrap, nearest[..9]);
        let (near, far) = nearest.split_at(9);
        let none = |peers: &[u8]| answering(peers.to_vec(), 50, || Ok(None));
        let holding = |peers: &[u8]| answering(peers.to_vec(), 100, || Ok(Some(held.clone())));
        let read = |answers| simulated_read(address, 0, 1..=7, bootstrap.clone(), answers);

        // The close group holds none. The eighth and ninth nearest seeds name
        // the state, three more of the nine hold none and the rest do not
        // answer: five answers, two naming it, and the state is the read's.
        // The seven farther seeds hold it too, and are never asked.
        let close_group = || answering(1..=7, 50, || Ok(None));
        let answers = joined([
            close_group(),
            none(&near[..3]),
            holding(&near[7..]),
            holding(far),
        ]);
        let (found, took, asked) = read(answers).await;
        assert_eq!(read_state_id(found), held.state_id());
        assert_eq!(took, Duration::from_millis(100));
        assert!(far.iter().all(|n| !asked.contains_key(n)), "{asked:?}");
        // Only the farther seeds hold it: the pointer is absent once the close
        // group and the nine have answered, each asked once.
        let (found, _, asked) = read(joined([close_group(), none(near), holding(far)])).await;
        assert!(found.expect("a read").is_none());
        let mut asked: Vec<(u8, usize)> = asked.into_iter().collect();
        asked.sort_unstable();
        let mut expected: Vec<(u8, usize)> = (1..=7)
            .chain(near.iter().copied())
            .map(|n| (n, 1))
            .collect();
        expected.sort_unstable();
        assert_eq!(asked, expected);
    }

    /// Once the close group has returned a state, the bootstrap peers stop at
    /// their quorum unless one names a newer state: an older copy one of them
    /// still holds does not keep the read open for a peer that never answers,
    /// while a newer one is waited for until a second peer confirms it.
    #[tokio::test(start_paused = true)]
    async fn the_bootstrap_peers_wait_only_for_a_state_newer_than_the_close_groups() {
        let (pk, sk) = keypair(20);
        let old = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let new = old.update(&sk, chunk_target(2)).expect("update");

        let mut answers = answering(1..=7, 50, || Ok(Some(new.clone())));
        answers.extend(answering([101], 50, || Ok(Some(old.clone()))));
        answers.extend(answering(102..=108, 50, || Ok(None)));
        let (found, took, _) = simulated_read(old.address(), 0, 1..=7, 101..=109, answers).await;
        assert_eq!(read_state_id(found), new.state_id());
        assert_eq!(took, Duration::from_millis(50));

        let mut answers = answering(1..=7, 50, || Ok(Some(old.clone())));
        answers.extend(answering([101], 50, || Ok(Some(new.clone()))));
        answers.extend(answering(102..=108, 50, || Ok(None)));
        answers.extend(answering([109], 2000, || Ok(Some(new.clone()))));
        let (found, took, _) = simulated_read(old.address(), 0, 1..=7, 101..=109, answers).await;
        assert_eq!(read_state_id(found), new.state_id());
        assert_eq!(took, Duration::from_secs(2));
    }

    /// A peer that is both in the close group and a bootstrap peer gets one
    /// GET, whose answer counts in both sets: whether it answered before the
    /// close group was known or is still being asked when it is.
    #[tokio::test(start_paused = true)]
    async fn a_peer_in_both_sets_is_asked_once() {
        let (pk, sk) = keypair(21);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let bootstrap = || (1..=3).chain(101..=106);
        for lookup in [50, 500] {
            let answers = answering((1..=7).chain(101..=106), 100, || Ok(Some(held.clone())));
            let (found, _, asked) =
                simulated_read(held.address(), lookup, 1..=7, bootstrap(), answers).await;
            assert_eq!(read_state_id(found), held.state_id());
            assert!(asked.values().all(|gets| *gets == 1), "{asked:?}");
            assert_eq!(asked.len(), 13);
        }
        // Three of the close group are bootstrap peers and answered before it
        // was known, one more answers once it is, and nobody else does: the
        // three still count towards the close group's quorum, so the read
        // returns its state rather than both sets' shortfall.
        let answers = answering(1..=4, 100, || Ok(Some(held.clone())));
        let (found, _, asked) =
            simulated_read(held.address(), 500, 1..=7, bootstrap(), answers).await;
        assert_eq!(read_state_id(found), held.state_id());
        assert!(asked.values().all(|gets| *gets == 1), "{asked:?}");
    }

    /// A bootstrap set of one peer is corroborated by that peer, as a close
    /// group of one is.
    #[tokio::test(start_paused = true)]
    async fn a_single_bootstrap_peer_corroborates_its_own_state() {
        let (pk, sk) = keypair(22);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let mut answers = answering(1..=7, 50, || Ok(None));
        answers.extend(answering([101], 50, || Ok(Some(held.clone()))));
        let (found, _, _) = simulated_read(held.address(), 0, 1..=7, [101], answers).await;
        assert_eq!(read_state_id(found), held.state_id());
    }

    /// Without bootstrap peers a read asks the close group alone, and stops as
    /// soon as its answer is settled.
    #[tokio::test(start_paused = true)]
    async fn without_bootstrap_peers_only_the_close_group_is_asked() {
        let (pk, sk) = keypair(23);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let mut answers = answering(1..=4, 50, || Ok(Some(held.clone())));
        answers.extend(answering(5..=7, 5000, || Ok(None)));
        let (found, took, asked) =
            simulated_read(held.address(), 0, 1..=7, std::iter::empty(), answers).await;
        assert_eq!(read_state_id(found), held.state_id());
        assert_eq!(took, Duration::from_millis(50));
        assert_eq!(asked.len(), 7);
    }

    /// A lookup that returns fewer peers than the close group does not shrink
    /// a read's quorum: one to three peers naming the same state are fewer
    /// than the four of seven a read needs, so the read fails with the close
    /// group's shortfall rather than return what they name, with or without
    /// bootstrap peers (here holding none).
    #[tokio::test(start_paused = true)]
    async fn a_read_of_a_short_lookup_is_a_shortfall_however_its_peers_agree() {
        let (pk, sk) = keypair(27);
        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        for found in 1..=3u8 {
            for bootstrap in [Vec::new(), (101..=109).collect::<Vec<u8>>()] {
                let mut answers = answering(1..=found, 50, || Ok(Some(held.clone())));
                answers.extend(answering(bootstrap.clone(), 50, || Ok(None)));
                let (read, _, _) =
                    simulated_read(held.address(), 0, 1..=found, bootstrap.clone(), answers).await;
                assert!(
                    matches!(&read, Err(Error::CloseGroupShortfall(message))
                        if message.starts_with(&format!("only {found} of the close group answered"))),
                    "a lookup of {found} peers, with {} bootstrap peers: {read:?}",
                    bootstrap.len()
                );
            }
        }
    }

    /// Refusals are counted as they arrive through the group, not only the
    /// first kept. One refusal among six silent peers is retried with the
    /// proof already paid for; a second makes it the answer.
    #[tokio::test]
    async fn refusals_are_counted_through_the_group_and_judged_by_how_many() {
        let group = |refusals: usize| {
            let in_flight: FuturesUnordered<BoxFuture<'static, Result<PutAck>>> =
                FuturesUnordered::new();
            for peer in 0..7 {
                in_flight.push(Box::pin(async move {
                    if peer < refusals {
                        Err(Error::Payment("pay up".to_string()))
                    } else {
                        Err(Error::Timeout("slow".to_string()))
                    }
                }));
            }
            in_flight
        };
        let address = [7u8; 32];
        let wanted = write_quorum(7);

        let one = ask_the_group(group(1), wanted, |_| true).await;
        assert_eq!(one.refusals, 1);
        let judged = judge_write(&address, 0, wanted, false, one);
        assert!(
            matches!(&judged, Err(e) if worth_retrying(e)),
            "one refusal among silent peers is retried, got {judged:?}"
        );

        let two = ask_the_group(group(2), wanted, |_| true).await;
        assert_eq!(two.refusals, 2);
        let judged = judge_write(&address, 0, wanted, false, two);
        assert!(
            matches!(&judged, Err(Error::Payment(_))),
            "two refusals with nobody storing are the answer, got {judged:?}"
        );
    }

    /// A node that cannot store a record just then, such as one whose disk is
    /// full, says nothing about the record. Two of them among five silent
    /// peers leave a round to retry with the same proof.
    #[tokio::test]
    async fn a_node_that_cannot_store_is_a_shortfall_not_a_refusal() {
        let in_flight: FuturesUnordered<BoxFuture<'static, Result<PutAck>>> =
            FuturesUnordered::new();
        for peer in 0..7 {
            in_flight.push(Box::pin(async move {
                if peer < 2 {
                    Err(Error::RemotePut {
                        address: String::new(),
                        source: ant_protocol::ProtocolError::StorageFailed("disk full".to_string()),
                    })
                } else {
                    Err(Error::Timeout("slow".to_string()))
                }
            }));
        }
        let wanted = write_quorum(7);
        let answered = ask_the_group(in_flight, wanted, |_| true).await;
        assert_eq!(answered.refusals, 0, "a full disk is not a refusal");
        let judged = judge_write(&[7u8; 32], 0, wanted, false, answered);
        assert!(
            matches!(&judged, Err(e) if worth_retrying(e)),
            "got {judged:?}"
        );
    }

    /// A write quorum and a read quorum must intersect at every group width.
    ///
    /// This is the property a fixed four-of-K silently broke: at K=20 a write
    /// on four peers and a read of a disjoint four would never meet, so an
    /// acknowledged pointer could read back as missing.
    #[test]
    fn write_and_read_quorums_overlap_by_the_corroboration_a_read_demands() {
        // The whole basis of the read rule: a state a write actually landed
        // must be reported by at least as many answering peers as a read
        // insists on, or a legitimate pointer would read back as unconfirmed.
        for k in 1usize..=64 {
            let write = write_quorum(k);
            let read = read_quorum(k);
            let needed = corroboration(k);
            assert!(
                write + read >= k + needed,
                "at width {k} a {write}-write and a {read}-read overlap in fewer \
                 than the {needed} peers a read requires"
            );
            assert!(write <= k, "a quorum cannot need more peers than exist");
            assert!(read <= k);
            assert!(
                needed <= read,
                "a read cannot need more backers than answers"
            );
        }
    }

    /// A pointer's state is paid for only once at least five of a close
    /// group of seven quoted it: the write quorum, counted over the group
    /// however small.
    #[test]
    fn a_pointer_state_needs_five_of_seven_quoting() {
        assert_eq!(pointer_write_quorum(7), 5);
        assert_eq!(pointer_write_quorum(7), write_quorum(quorum_width(3, 7)));
    }

    /// The default close group is seven: four answers decide a read, five
    /// stores make a write, and two peers must name what a read returns.
    #[test]
    fn the_default_group_reads_on_four_and_writes_on_five() {
        assert_eq!(read_quorum(7), 4);
        assert_eq!(write_quorum(7), 5);
        assert_eq!(corroboration(7), 2);

        assert_eq!(read_quorum(20), 11);
        assert_eq!(write_quorum(20), 12);

        // A group of one cannot corroborate itself with anyone else.
        assert_eq!(read_quorum(1), 1);
        assert_eq!(write_quorum(1), 1);
        assert_eq!(corroboration(1), 1);
    }

    /// A quorum of nothing is satisfied by nothing.
    ///
    /// `write_quorum(0)` is zero, so a write to an empty group would count zero
    /// acknowledgements as enough and report a paid record as stored on no
    /// peers at all. Both paths refuse an empty group before that arithmetic
    /// is ever reached.
    #[test]
    fn an_empty_group_is_not_a_quorum() {
        assert_eq!(
            write_quorum(0),
            0,
            "which is exactly why an empty group must be refused earlier"
        );
        assert_eq!(corroboration(0), 0, "and nothing can corroborate nothing");
        for k in 1usize..=64 {
            assert!(write_quorum(k) >= 1, "a real group always needs a storer");
            assert!(
                corroboration(k) >= 1,
                "and a real answer always needs a peer"
            );
        }
    }

    /// One peer must not be able to decide what a pointer says.
    ///
    /// The attack this closes: an owner signs a state without paying for it and
    /// one close-group peer serves it. Every honest peer says `NotFound`, the
    /// record verifies and belongs at the address, and it wins the merge — so a
    /// read that took the best answer regardless of who backed it would hand
    /// back a state the network never stored.
    #[test]
    fn a_state_only_one_peer_reports_is_not_the_networks_answer() {
        let (pk, sk) = keypair(11);
        let unpaid = Pointer::sign(&sk, &pk, 900, chunk_target(9)).expect("sign");
        let stored = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");

        // One peer offers the unpaid state; the rest of the close group has
        // never heard of it.
        let seen = tally(vec![Some(unpaid.clone()), None, None, None]);
        assert!(seen.any(), "a state was offered");
        assert!(
            seen.corroborated(corroboration(7)).is_none(),
            "but one peer naming it is one peer deciding, not an answer"
        );

        // A state the group really holds clears the bar.
        let seen = tally(vec![Some(stored.clone()), Some(stored.clone()), None]);
        assert_eq!(
            seen.corroborated(corroboration(7))
                .expect("an answer")
                .state_id(),
            stored.state_id()
        );
    }

    /// A chain that points at itself must be caught by the seen-set, not by
    /// running out of hops: the node never reads a target, so a cycle is the
    /// client's to detect.
    #[test]
    fn a_self_referencing_chain_is_a_cycle() {
        let (pk, sk) = keypair(8);
        let address = pointer_address(&pk);
        let loops = Pointer::sign(
            &sk,
            &pk,
            0,
            PointerTarget::new(PointerTargetKind::Pointer, address),
        )
        .expect("sign");

        // The walk `pointer_resolve` performs, without the network: the first
        // hop lands back on the address already visited.
        let mut seen = HashSet::new();
        assert!(seen.insert(loops.address()));
        assert!(
            !seen.insert(loops.target().address),
            "a pointer targeting its own address is a cycle the client must refuse"
        );
    }

    /// The final state handing `sk`'s pointer over to `recipient`.
    fn handed_to(pk: &MlDsaPublicKey, sk: &MlDsaSecretKey, recipient: u8) -> Pointer {
        Pointer::sign(
            sk,
            pk,
            FINAL_COUNTER,
            PointerTarget::new(PointerTargetKind::Pointer, [recipient; 32]),
        )
        .expect("sign")
    }

    fn state_of(chosen: Chosen<'_>) -> Option<XorName> {
        match chosen {
            Chosen::State(state) => state.map(Pointer::state_id),
            Chosen::Forked => panic!("expected a state, got a fork"),
        }
    }

    /// A transfer every peer holds is the answer, and the read settles on a
    /// majority of them.
    #[test]
    fn a_transfer_the_group_holds_is_read_back() {
        let (pk, sk) = keypair(40);
        let before = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let transfer = handed_to(&pk, &sk, 0x77);

        let mut seen = Replies::default();
        for _ in 0..3 {
            seen.add(Some(transfer.clone()));
            assert!(
                !seen.settled(2, 4),
                "a final state short of a majority does not settle a read"
            );
        }
        seen.add(Some(before.clone()));
        seen.add(Some(transfer.clone()));
        assert!(seen.settled(2, 4));
        assert_eq!(state_of(seen.chosen(2, 4)), Some(transfer.state_id()));
    }

    /// Two final states are unordered, so the merge rule cannot pick one; the
    /// one a majority holds is what most nodes took first, and is the answer
    /// whichever order the replies arrive in, even though the other's target
    /// sorts first.
    #[test]
    fn of_two_final_states_the_majority_is_read_in_any_order() {
        let (pk, sk) = keypair(41);
        let established = handed_to(&pk, &sk, 0x77);
        let late = handed_to(&pk, &sk, 0x01);
        assert!(late.target().to_bytes() < established.target().to_bytes());

        let mut replies = vec![Some(late.clone()), Some(late.clone())];
        replies.extend((0..5).map(|_| Some(established.clone())));
        for rotation in 0..replies.len() {
            let mut order = replies.clone();
            order.rotate_left(rotation);
            let seen = tally(order);
            assert!(seen.settled(2, 4));
            assert_eq!(
                state_of(seen.chosen(2, 4)),
                Some(established.state_id()),
                "rotation {rotation}"
            );
        }
    }

    /// Two final states and no majority: there is no answer, and saying so is
    /// the only honest read. The read is never settled early, so it asks the
    /// whole group before concluding it.
    #[test]
    fn two_final_states_without_a_majority_are_a_fork() {
        let (pk, sk) = keypair(42);
        let before = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let one = handed_to(&pk, &sk, 0x77);
        let other = handed_to(&pk, &sk, 0x01);

        let seen = tally(vec![
            Some(one.clone()),
            Some(one.clone()),
            Some(one.clone()),
            Some(other.clone()),
            Some(other.clone()),
            Some(before.clone()),
            Some(before.clone()),
        ]);
        assert!(!seen.settled(2, 4));
        assert!(matches!(seen.chosen(2, 4), Chosen::Forked));

        // Even a lone peer holding the other side is evidence of a fork: only
        // the owner could have signed it.
        let seen = tally(vec![
            Some(one.clone()),
            Some(one.clone()),
            Some(one.clone()),
            Some(other.clone()),
            Some(before.clone()),
            Some(before.clone()),
            None,
        ]);
        assert!(matches!(seen.chosen(2, 4), Chosen::Forked));
    }

    /// One final state short of a majority and nothing contesting it is a
    /// transfer still spreading. It is returned once corroborated, as any state
    /// is, and one peer's word is not enough.
    #[test]
    fn one_uncontested_final_state_is_read_once_corroborated() {
        let (pk, sk) = keypair(43);
        let before = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let transfer = handed_to(&pk, &sk, 0x77);

        let spreading = tally(vec![
            Some(transfer.clone()),
            Some(transfer.clone()),
            Some(before.clone()),
            Some(before.clone()),
            Some(before.clone()),
        ]);
        assert_eq!(state_of(spreading.chosen(2, 4)), Some(transfer.state_id()));

        let lone = tally(vec![
            Some(transfer.clone()),
            Some(before.clone()),
            Some(before.clone()),
            Some(before.clone()),
        ]);
        assert_eq!(state_of(lone.chosen(2, 4)), Some(before.state_id()));
    }

    /// The whole-group check a recipient runs before relying on a transfer.
    #[test]
    fn finality_names_each_case_a_recipient_must_tell_apart() {
        let (pk, sk) = keypair(44);
        let before = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let transfer = handed_to(&pk, &sk, 0x77);
        let rival = handed_to(&pk, &sk, 0x01);
        let frozen = Pointer::sign(&sk, &pk, FINAL_COUNTER, chunk_target(5)).expect("sign");
        let group = 7;

        let open = finality_status(&tally(vec![Some(before.clone()); 7]), group, group);
        assert_eq!(open, FinalityStatus::Open { counter: Some(0) });

        let status = finality_status(
            &tally(vec![
                Some(transfer.clone()),
                Some(transfer.clone()),
                Some(transfer.clone()),
                Some(transfer.clone()),
                Some(before.clone()),
                None,
                None,
            ]),
            group,
            group,
        );
        match &status {
            FinalityStatus::Final(state) => {
                assert_eq!(state.state_id, transfer.state_id());
                assert_eq!(state.holders, 4);
                assert_eq!(state.transferred_to(), Some([0x77; 32]));
            }
            other => panic!("expected Final, got {other:?}"),
        }

        let status = finality_status(
            &tally(vec![
                Some(transfer.clone()),
                Some(transfer.clone()),
                Some(before.clone()),
            ]),
            group,
            3,
        );
        assert!(matches!(status, FinalityStatus::Settling(ref s) if s.holders == 2));

        let status = finality_status(
            &tally(vec![
                Some(rival.clone()),
                Some(transfer.clone()),
                Some(transfer.clone()),
                Some(transfer.clone()),
                Some(transfer.clone()),
            ]),
            group,
            5,
        );
        match status {
            FinalityStatus::Forked { states, majority } => {
                assert_eq!(states.len(), 2);
                assert_eq!(
                    states.first().map(|s| s.state_id),
                    Some(transfer.state_id()),
                    "most-held first"
                );
                assert_eq!(majority.map(|s| s.state_id), Some(transfer.state_id()));
            }
            other => panic!("expected Forked, got {other:?}"),
        }

        let status = finality_status(&tally(vec![Some(frozen.clone()); 7]), group, group);
        match status {
            FinalityStatus::Final(state) => assert_eq!(state.transferred_to(), None),
            other => panic!("expected a frozen Final, got {other:?}"),
        }
    }

    /// Four of seven report the transfer and three do not answer. One of the
    /// three could hold a rival, so this is not yet final; a recipient that
    /// relied on it could be relying on the minority side of a fork.
    #[test]
    fn a_majority_is_not_final_while_part_of_the_group_is_silent() {
        let (pk, sk) = keypair(47);
        let transfer = handed_to(&pk, &sk, 0x77);
        let status = finality_status(&tally(vec![Some(transfer.clone()); 4]), 7, 4);
        assert!(
            matches!(&status, FinalityStatus::Unconfirmed(state) if state.holders == 4),
            "got {status:?}"
        );
        let finality = PointerFinality {
            address: transfer.address(),
            group: 7,
            answered: 4,
            status,
            seeds: None,
        };
        assert!(!finality.is_final());
        assert_eq!(finality.transferred_to(), None);

        // And a rival already seen still refuses a transfer it would fork.
        let other = handed_to(&pk, &sk, 0x01);
        assert!(matches!(
            rival_final(&finality, &other),
            Some(Error::PointerFinal(_))
        ));
        assert!(rival_final(&finality, &transfer).is_none());
    }

    /// The recipient walk, over pointers held in a map.
    async fn walk(
        chain: &HashMap<XorName, Pointer>,
        address: XorName,
        recipient: XorName,
    ) -> Result<()> {
        check_recipient_chain(&address, &recipient, |at| {
            let found = chain.get(&at).cloned();
            async move { Ok(found) }
        })
        .await
    }

    /// A chain of `hops` pointers from `[1; 32]`, each targeting the next,
    /// the last targeting `end`.
    fn chain_to(hops: u8, end: PointerTarget) -> HashMap<XorName, Pointer> {
        (1..=hops)
            .map(|hop| {
                let (pk, sk) = keypair(hop);
                let target = if hop == hops {
                    end
                } else {
                    PointerTarget::new(
                        PointerTargetKind::Pointer,
                        pointer_address(&keypair(hop + 1).0),
                    )
                };
                let record = Pointer::create(&sk, &pk, target).expect("create");
                (record.address(), record)
            })
            .collect()
    }

    /// Readers of the source read it and then every recipient hop, so the
    /// recipient's chain gets one hop fewer than a resolve allows. A chain
    /// that returns to the source at the very last hop is a cycle, and one
    /// too long to follow is refused rather than let through unchecked.
    #[tokio::test]
    async fn a_recipient_chain_is_checked_to_the_last_hop_a_reader_takes() {
        let (source_pk, _) = keypair(200);
        let source = pointer_address(&source_pk);
        let back = PointerTarget::new(PointerTargetKind::Pointer, source);
        let first = pointer_address(&keypair(1).0);
        let allowed = u8::try_from(MAX_POINTER_RESOLVE_DEPTH - 1).expect("small");

        let ends = chain_to(allowed, chunk_target(9));
        assert!(
            walk(&ends, source, first).await.is_ok(),
            "the longest chain a reader can follow"
        );

        let cycles_at_the_end = chain_to(allowed, back);
        assert!(
            matches!(walk(&cycles_at_the_end, source, first).await, Err(Error::InvalidData(m)) if m.contains("cycle")),
            "a chain back to the source at its last hop is a cycle"
        );

        let too_long = chain_to(allowed + 1, chunk_target(9));
        assert!(
            matches!(walk(&too_long, source, first).await, Err(Error::InvalidData(m)) if m.contains("longer")),
            "a chain no reader could follow is refused"
        );

        // One hop longer and back to the source: the walk runs out exactly
        // as it reaches the source, which must not pass as no cycle.
        let cycles_past_the_end = chain_to(allowed + 1, back);
        assert!(walk(&cycles_past_the_end, source, first).await.is_err());

        let nowhere = HashMap::new();
        assert!(
            matches!(walk(&nowhere, source, first).await, Err(Error::InvalidData(m)) if m.contains("does not exist")),
        );
    }

    /// A resolve, over pointers held in a map.
    async fn resolve(chain: &HashMap<XorName, Pointer>, from: XorName) -> Result<PointerTarget> {
        resolve_chain(&from, |at| {
            let found = chain.get(&at).cloned();
            async move { Ok(found) }
        })
        .await
    }

    /// A resolve refuses what the node cannot: it never reads a target, so a
    /// cycle, a broken chain and an over-long chain are all the client's to
    /// stop. The depth limit is checked on both sides of the boundary.
    #[tokio::test]
    async fn a_resolve_refuses_cycles_broken_chains_and_chains_past_its_depth() {
        let first = pointer_address(&keypair(1).0);
        let depth = u8::try_from(MAX_POINTER_RESOLVE_DEPTH).expect("small");

        // A pointer that targets itself.
        let (pk, sk) = keypair(210);
        let own = pointer_address(&pk);
        let looped = Pointer::create(
            &sk,
            &pk,
            PointerTarget::new(PointerTargetKind::Pointer, own),
        )
        .expect("create");
        let chain = HashMap::from([(own, looped)]);
        let err = resolve(&chain, own)
            .await
            .expect_err("a cycle must not resolve");
        assert!(err.to_string().contains("cycles back"), "got: {err}");

        // A pointer to a pointer nobody wrote.
        let nobody = pointer_address(&keypair(211).0);
        let dangling = chain_to(1, PointerTarget::new(PointerTargetKind::Pointer, nobody));
        let err = resolve(&dangling, first)
            .await
            .expect_err("a broken chain must not resolve");
        assert!(err.to_string().contains("breaks at"), "got: {err}");

        // Exactly the limit resolves to the chunk at its end; one pointer
        // more does not.
        let at_the_limit = chain_to(depth, chunk_target(9));
        assert_eq!(
            resolve(&at_the_limit, first)
                .await
                .expect("a chain of exactly the limit resolves"),
            chunk_target(9)
        );
        let too_long = chain_to(depth + 1, chunk_target(9));
        let err = resolve(&too_long, first)
            .await
            .expect_err("a chain past the limit must not resolve");
        assert!(
            err.to_string()
                .contains(&format!("longer than {MAX_POINTER_RESOLVE_DEPTH} hops")),
            "got: {err}"
        );
    }

    /// A transfer whose write reported failure, judged by the group after it:
    /// a rival names the refusal, the transfer's own state on a majority is a
    /// transfer that landed with its acknowledgements lost, and anything else
    /// is the write's own error.
    #[test]
    fn a_transfer_the_group_holds_is_done_whatever_its_acknowledgements_said() {
        let (pk, sk) = keypair(48);
        let ours = handed_to(&pk, &sk, 0x77);
        let theirs = handed_to(&pk, &sk, 0x01);
        let finality = |status, answered| PointerFinality {
            address: ours.address(),
            group: 7,
            answered,
            status,
            seeds: None,
        };
        let lost = || Error::Timeout("no acknowledgement".to_string());

        let landed = after_failed_transfer(
            lost(),
            Ok(finality(FinalityStatus::Final(FinalState::of(&ours, 6)), 7)),
            &ours,
        );
        assert!(
            matches!(&landed, Ok(finality)
                if matches!(&finality.status, FinalityStatus::Final(state)
                    if state.state_id == ours.state_id())),
            "got {landed:?}"
        );
        assert!(after_failed_transfer(
            lost(),
            Ok(finality(
                FinalityStatus::Unconfirmed(FinalState::of(&ours, 4)),
                5
            )),
            &ours,
        )
        .is_ok());

        assert!(matches!(
            after_failed_transfer(
                lost(),
                Ok(finality(
                    FinalityStatus::Final(FinalState::of(&theirs, 6)),
                    7
                )),
                &ours,
            ),
            Err(Error::PointerFinal(_))
        ));
        assert!(matches!(
            after_failed_transfer(
                lost(),
                Ok(finality(
                    FinalityStatus::Settling(FinalState::of(&ours, 2)),
                    7
                )),
                &ours,
            ),
            Err(Error::Timeout(_))
        ));
        assert!(matches!(
            after_failed_transfer(lost(), Err(Error::Timeout("group".to_string())), &ours),
            Err(Error::Timeout(message)) if message == "no acknowledgement"
        ));
    }

    /// An update is refused for any final state the group shows, however few
    /// hold it.
    #[test]
    fn any_final_state_refuses_an_update() {
        let (pk, sk) = keypair(49);
        let transfer = handed_to(&pk, &sk, 0x77);
        let finality = |status| PointerFinality {
            address: transfer.address(),
            group: 7,
            answered: 7,
            status,
            seeds: None,
        };
        assert!(final_already(&finality(FinalityStatus::Open { counter: Some(3) })).is_none());
        for status in [
            FinalityStatus::Settling(FinalState::of(&transfer, 1)),
            FinalityStatus::Unconfirmed(FinalState::of(&transfer, 4)),
            FinalityStatus::Final(FinalState::of(&transfer, 7)),
        ] {
            assert!(matches!(
                final_already(&finality(status)),
                Some(Error::PointerFinal(_))
            ));
        }
    }

    /// A transfer refused because the pointer was already final on another
    /// state is reported as that, and one that landed is not a refusal.
    #[test]
    fn a_refused_transfer_names_the_final_state_that_beat_it() {
        let (pk, sk) = keypair(45);
        let ours = handed_to(&pk, &sk, 0x77);
        let theirs = handed_to(&pk, &sk, 0x01);
        let finality = |status| PointerFinality {
            address: ours.address(),
            group: 7,
            answered: 7,
            status,
            seeds: None,
        };

        let beaten = finality(FinalityStatus::Final(FinalState::of(&theirs, 7)));
        assert!(matches!(
            rival_final(&beaten, &ours),
            Some(Error::PointerFinal(_))
        ));
        let landed = finality(FinalityStatus::Final(FinalState::of(&ours, 7)));
        assert!(rival_final(&landed, &ours).is_none());
        assert!(rival_final(&finality(FinalityStatus::Open { counter: Some(3) }), &ours).is_none());
        let forked = finality(FinalityStatus::Forked {
            states: vec![FinalState::of(&ours, 3), FinalState::of(&theirs, 3)],
            majority: None,
        });
        assert!(matches!(
            rival_final(&forked, &ours),
            Some(Error::PointerForked(_))
        ));
    }

    /// A read over a group split by a fork asks everyone, then reports it.
    #[tokio::test(start_paused = true)]
    async fn a_read_of_a_forked_pointer_asks_the_whole_group() {
        let (pk, sk) = keypair(46);
        let one = handed_to(&pk, &sk, 0x77);
        let other = handed_to(&pk, &sk, 0x01);
        let address = one.address();
        let (first, second) = (Some(Some(&one)), Some(Some(&other)));
        let split = || {
            in_turn(vec![
                first,
                first,
                second,
                second,
                first,
                second,
                Some(None),
            ])
        };
        let forked = |found: &Result<Option<Pointer>>| {
            matches!(found, Err(Error::PointerForked(message))
                if message.contains("none is held by 4 of the 7 close-group peers"))
        };

        // No majority, so nobody is skipped: the read ends with the seventh
        // answer, at 70 ms.
        let (found, took, _) = simulated_read(address, 0, 1..=7, std::iter::empty(), split()).await;
        assert!(forked(&found), "{found:?}");
        assert_eq!(took, Duration::from_millis(70));

        // With a majority it stops as soon as the majority is heard: the
        // fourth peer naming the same final state, the fifth to answer.
        let (found, took, _) = simulated_read(
            address,
            0,
            1..=7,
            std::iter::empty(),
            in_turn(vec![second, first, first, first, first, second, first]),
        )
        .await;
        assert_eq!(read_state_id(found), one.state_id());
        assert_eq!(took, Duration::from_millis(50));

        // Asked beside the close group and two more peers, the bootstrap
        // peers see the fork too, and the close group's is the answer.
        let answers = joined([split(), answering(101..=102, 5, || Ok(None))]);
        let (found, took, _) =
            simulated_read(address, 0, 1..=7, (1..=7).chain(101..=102), answers).await;
        assert!(forked(&found), "{found:?}");
        assert_eq!(took, Duration::from_millis(70));
    }

    /// The close group's fork is the read's answer whatever the bootstrap
    /// peers name. The bootstrap peers' fork is the answer only when the close
    /// group answered and holds no final state; beside a close group that
    /// failed, the close group's failure is.
    #[test]
    fn a_bootstrap_fork_counts_only_where_the_close_group_holds_no_final_state() {
        let (pk, sk) = keypair(26);
        let open = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let transfer = handed_to(&pk, &sk, 0x77);
        let fork = || Error::PointerForked("two final states".to_string());
        let set = |outcome: Result<Option<Pointer>>| {
            let seen = outcome.as_ref().ok().cloned().flatten();
            SetRead { outcome, seen }
        };

        let read = newest_pointer(set(Err(fork())), set(Ok(Some(transfer.clone()))));
        assert!(matches!(read, Err(Error::PointerForked(_))), "{read:?}");
        for close_group in [Ok(None), Ok(Some(open.clone()))] {
            let read = newest_pointer(set(close_group), set(Err(fork())));
            assert!(matches!(read, Err(Error::PointerForked(_))), "{read:?}");
        }
        let read = newest_pointer(set(Ok(Some(transfer.clone()))), set(Err(fork())));
        assert_eq!(read_state_id(read), transfer.state_id());
        let shortfall = || Error::CloseGroupShortfall("only 3 of the close group answered".into());
        let read = newest_pointer(set(Err(shortfall())), set(Err(fork())));
        assert!(
            matches!(read, Err(Error::CloseGroupShortfall(_))),
            "{read:?}"
        );
    }

    /// An unknown target kind is carried, not rejected: the record is signed, so
    /// the bytes are authentic even when this build cannot follow them.
    #[test]
    fn an_unknown_target_kind_is_carried_not_rejected() {
        let (pk, sk) = keypair(7);
        let exotic = PointerTarget::from_raw_tag(200, [9; 32]);
        let record = Pointer::sign(&sk, &pk, 0, exotic).expect("sign");
        let parsed = Pointer::from_bytes(&record.to_bytes()).expect("parse");
        assert_eq!(parsed.target().kind_tag(), 200);
        assert_eq!(parsed.target().kind(), None);
    }

    /// A finality check as `pointer_finality` makes one with the default
    /// close-group size, on a simulated network in paused time: the close
    /// group's census, then, while it shows the pointer open, the read of the
    /// close group and `bootstrap`. Each peer gives its answer from `answers`
    /// every time it is asked, or times out after ten seconds when it has
    /// none. Returns the check, and how many GETs each peer was sent.
    async fn simulated_finality(
        address: XorName,
        close_group: impl IntoIterator<Item = u8>,
        bootstrap: impl IntoIterator<Item = u8>,
        answers: Answers,
    ) -> (Result<PointerFinality>, HashMap<u8, usize>) {
        let close_group: Vec<(PeerId, Vec<MultiAddr>)> = close_group
            .into_iter()
            .map(|n| (id(n), Vec::new()))
            .collect();
        let bootstrap: Vec<(PeerId, Vec<MultiAddr>)> =
            bootstrap.into_iter().map(|n| (id(n), Vec::new())).collect();
        let answers: HashMap<PeerId, (Duration, Result<Option<Pointer>>)> = answers
            .into_iter()
            .map(|(n, after, reply)| (id(n), (after, reply)))
            .collect();
        let asked = std::cell::RefCell::new(HashMap::new());
        let finality = pointer_finality_from(
            &address,
            || {
                let close_group = close_group.clone();
                async move { Ok::<_, Error>(close_group) }
            },
            ant_protocol::CLOSE_GROUP_SIZE,
            &bootstrap,
            |peer, _| {
                *asked.borrow_mut().entry(peer.as_bytes()[0]).or_insert(0) += 1;
                let (after, reply) = match answers.get(&peer) {
                    Some((after, Ok(state))) => (*after, Ok(state.clone())),
                    _ => (Duration::from_secs(10), silent()),
                };
                async move {
                    tokio::time::sleep(after).await;
                    reply
                }
            },
            |_| false,
            &[],
        )
        .await
        .0;
        (finality, asked.into_inner())
    }

    /// Every peer of the close group answers that it holds no state, and the
    /// bootstrap peers agree on one: the pointer is open at that state's
    /// counter, the state a read returns, not open with no state. What the
    /// bootstrap peers hold is shown.
    #[tokio::test(start_paused = true)]
    async fn finality_counts_a_state_only_the_bootstrap_peers_hold() {
        let (pk, sk) = keypair(50);
        let mut held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        for target in 2..=4 {
            held = held.update(&sk, chunk_target(target)).expect("update");
        }
        assert_eq!(held.counter(), 3);
        let mut answers = answering(1..=7, 50, || Ok(None));
        answers.extend(answering(101..=105, 100, || Ok(Some(held.clone()))));
        answers.extend(answering(106..=109, 200, || Ok(None)));
        let (finality, asked) = simulated_finality(held.address(), 1..=7, 101..=109, answers).await;
        let finality = finality.expect("a check");
        assert_eq!(finality.status, FinalityStatus::Open { counter: Some(3) });
        assert_eq!((finality.group, finality.answered), (7, 7));
        let seeds = finality.seeds.expect("the bootstrap peers were asked");
        assert_eq!((seeds.asked, seeds.answered), (9, 5));
        let state = seeds.state.expect("the state they agree on");
        assert_eq!(state.state_id, held.state_id());
        assert_eq!((state.counter, state.holders), (3, 5));
        assert!(!state.is_final());
        assert_eq!(state.transferred_to(), None);
        // The close group was asked by the census and again by the read.
        assert!((1..=7).all(|n| asked.get(&n) == Some(&2)), "{asked:?}");
    }

    /// The close group holds counter 1 and the bootstrap peers counter 2:
    /// the newer is the state a read returns, and its counter is reported.
    #[tokio::test(start_paused = true)]
    async fn finality_reports_a_newer_state_the_bootstrap_peers_hold() {
        let (pk, sk) = keypair(51);
        let older = Pointer::create(&sk, &pk, chunk_target(1))
            .expect("create")
            .update(&sk, chunk_target(2))
            .expect("update");
        let newer = older.update(&sk, chunk_target(3)).expect("update");
        let mut answers = answering(1..=7, 50, || Ok(Some(older.clone())));
        answers.extend(answering(101..=109, 100, || Ok(Some(newer.clone()))));
        let (finality, _) = simulated_finality(older.address(), 1..=7, 101..=109, answers).await;
        assert_eq!(
            finality.expect("a check").status,
            FinalityStatus::Open { counter: Some(2) }
        );
    }

    /// The bootstrap peers hold a transfer the close group doesn't: the
    /// pointer is settling on it, held by no peer of the close group, never
    /// open, and not final.
    #[tokio::test(start_paused = true)]
    async fn a_final_state_only_the_bootstrap_peers_hold_is_settling_not_open() {
        let (pk, sk) = keypair(52);
        let before = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let transfer = handed_to(&pk, &sk, 0x77);
        let mut answers = answering(1..=7, 50, || Ok(Some(before.clone())));
        answers.extend(answering(101..=109, 100, || Ok(Some(transfer.clone()))));
        let (finality, _) = simulated_finality(before.address(), 1..=7, 101..=109, answers).await;
        let finality = finality.expect("a check");
        match &finality.status {
            FinalityStatus::Settling(state) => {
                assert_eq!(state.state_id, transfer.state_id());
                assert_eq!(state.holders, 0, "no peer of the close group holds it");
                assert_eq!(state.transferred_to(), Some([0x77; 32]));
            }
            other => panic!("expected Settling, got {other:?}"),
        }
        assert!(!finality.is_final());
        assert_eq!(finality.transferred_to(), None);
        let state = finality
            .seeds
            .clone()
            .expect("asked")
            .state
            .expect("the transfer");
        assert!(state.is_final());
        assert_eq!(state.transferred_to(), Some([0x77; 32]));
        // A transfer a check settles on is refused, as one the close group
        // holds is.
        assert!(matches!(
            rival_final(&finality, &handed_to(&pk, &sk, 0x01)),
            Some(Error::PointerFinal(_))
        ));
    }

    /// Neither the close group nor any bootstrap peer holds a state: open
    /// with no state, reported only once every bootstrap peer has answered.
    #[tokio::test(start_paused = true)]
    async fn finality_reports_no_state_only_once_every_bootstrap_peer_answered() {
        let (pk, _) = keypair(53);
        let address = pointer_address(&pk);
        let mut answers = answering(1..=7, 50, || Ok(None));
        answers.extend(answering(101..=108, 100, || Ok(None)));
        answers.extend(answering([109], 3_000, || Ok(None)));
        let started = tokio::time::Instant::now();
        let (finality, _) = simulated_finality(address, 1..=7, 101..=109, answers).await;
        let finality = finality.expect("a check");
        assert_eq!(finality.status, FinalityStatus::Open { counter: None });
        assert!(
            started.elapsed() >= Duration::from_secs(3),
            "the last bootstrap peer is waited for"
        );
        let seeds = finality.seeds.expect("asked");
        assert_eq!((seeds.asked, seeds.answered), (9, 9));
        assert_eq!(seeds.state, None);
    }

    /// Two bootstrap peers name a newer state than the close group holds,
    /// and the others don't answer: the check fails as a read of the
    /// pointer does, rather than call it open at the older counter.
    #[tokio::test(start_paused = true)]
    async fn a_bootstrap_shortfall_naming_a_newer_state_fails_as_a_read_does() {
        let (pk, sk) = keypair(54);
        let older = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let newer = older.update(&sk, chunk_target(2)).expect("update");
        let answers = || {
            let mut answers = answering(1..=7, 50, || Ok(Some(older.clone())));
            answers.extend(answering(101..=102, 100, || Ok(Some(newer.clone()))));
            answers
        };
        let (finality, _) = simulated_finality(older.address(), 1..=7, 101..=109, answers()).await;
        let (read, _, _) = simulated_read(older.address(), 0, 1..=7, 101..=109, answers()).await;
        let read = read.expect_err("a read fails");
        let finality = finality.expect_err("so does the check");
        assert!(
            matches!(&finality, Error::CloseGroupShortfall(message)
                if message.starts_with("only 2 of the bootstrap peers answered")),
            "{finality:?}"
        );
        assert_eq!(finality.to_string(), read.to_string());
    }

    /// A final state the close group holds, or two, is the close group's to
    /// report: no bootstrap peer is asked and none is shown. Without
    /// bootstrap peers an open pointer is read from the close group alone.
    #[tokio::test(start_paused = true)]
    async fn the_close_group_decides_final_states_and_reads_alone_without_bootstrap_peers() {
        let (pk, sk) = keypair(55);
        let transfer = handed_to(&pk, &sk, 0x77);
        let mut answers = answering(1..=7, 50, || Ok(Some(transfer.clone())));
        answers.extend(answering(101..=109, 50, || Ok(None)));
        let (finality, asked) =
            simulated_finality(transfer.address(), 1..=7, 101..=109, answers).await;
        let finality = finality.expect("a check");
        assert!(finality.is_final());
        assert_eq!(finality.seeds, None);
        assert!((101..=109).all(|n| !asked.contains_key(&n)), "{asked:?}");

        let held = Pointer::create(&sk, &pk, chunk_target(1)).expect("create");
        let (finality, _) = simulated_finality(
            held.address(),
            1..=7,
            std::iter::empty(),
            answering(1..=7, 50, || Ok(Some(held.clone()))),
        )
        .await;
        let finality = finality.expect("a check");
        assert_eq!(finality.status, FinalityStatus::Open { counter: Some(0) });
        assert_eq!(finality.seeds, None);
    }
}
