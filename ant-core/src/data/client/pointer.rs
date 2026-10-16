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

use std::collections::HashSet;
use std::future::Future;

use ant_protocol::chunk::{
    ChunkMessage, ChunkMessageBody, PointerGetRequest, PointerGetResponse, PointerPutRequest,
    PointerPutResponse,
};
use ant_protocol::pointer::{
    pointer_address, Pointer, PointerTarget, PointerTargetKind, DATA_TYPE_POINTER, POINTER_WIRE_LEN,
};
use ant_protocol::pqc::api::{MlDsaPublicKey, MlDsaSecretKey};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::XorName;
use bytes::Bytes;
use futures::future::{select, Either};
use futures::stream::{FuturesUnordered, StreamExt};
use tracing::{debug, warn};
use web_time::Duration;

use crate::client_engine::{store_retry_delay, STORE_MAX_RETRIES};
use crate::data::client::batch::ChunkPaymentPlan;
use crate::data::client::chunk::STORE_RESPONSE_TIMEOUT;
use crate::data::client::Client;
use crate::data::error::{Error, Result};
use crate::data::network::send_and_await_chunk_response;
use crate::runtime::sleep;

/// How many of `peers` must answer a read.
///
/// Derived from the group actually returned, not from a fixed constant: the
/// close-group width is configurable, and a fixed four against a width of
/// twenty would let a write land on four peers and a *disjoint* four answer the
/// read. Quorums only intersect if both are taken from the same set.
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
}

impl Answered {
    /// What to report when too few answered: a refusal if any peer gave one,
    /// since it says why, else the last failure.
    fn failure(self) -> Option<Error> {
        self.refusal.or(self.last_error)
    }

    /// Keep a peer's failure: the first refusal, else the latest failure.
    fn fail(&mut self, e: Error) {
        if self.refusal.is_none() && !worth_retrying(&e) {
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
/// The read needs [`read_quorum`] of the set to answer and returns the best
/// state at least [`corroboration`] of them name, both taken from the set's own
/// size.
struct ReadTally {
    /// How many peers the set has.
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

    /// Whether [`read_quorum`] of the set has answered.
    fn has_quorum(&self) -> bool {
        self.answered.count >= read_quorum(self.peers)
    }

    /// The best state at least [`corroboration`] of the answers name.
    fn corroborated(&self) -> Option<&Pointer> {
        self.replies.corroborated(corroboration(self.peers))
    }

    /// Whether the read of this set alone would stop here. Answers alone settle
    /// a read that found nothing. A state is settled only once enough peers have
    /// named it — until then the read keeps asking, because the peers that would
    /// confirm it may simply not have answered yet.
    fn settled(&self) -> bool {
        self.has_quorum() && (!self.replies.any() || self.corroborated().is_some())
    }

    /// The state this set returns, once it has one.
    fn state(&self) -> Option<&Pointer> {
        self.corroborated().filter(|_| self.has_quorum())
    }

    /// Whether any answer names a state that replaces `held`.
    fn names_newer_than(&self, held: &Pointer) -> bool {
        self.replies
            .seen
            .iter()
            .any(|(state, _)| state.replaces(held))
    }

    /// The set's outcome, and the state its answers corroborate even when too
    /// few of the set answered for that to be the outcome.
    fn finish(self, address: &XorName, asked: Asked) -> SetRead {
        let seen = self.corroborated().cloned();
        SetRead {
            outcome: self.outcome(address, asked),
            seen,
        }
    }

    fn outcome(self, address: &XorName, asked: Asked) -> Result<Option<Pointer>> {
        let needed = corroboration(self.peers);
        let corroborated = self.corroborated().cloned();
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
/// `in_flight` holds their verified replies, and `peers` is how many there are.
/// It stops as soon as the set's answer is settled, and the requests still in
/// flight are dropped, so one slow peer cannot stall the read behind the store
/// timeout.
async fn read_pointer_from(
    mut in_flight: FuturesUnordered<impl Future<Output = Result<Option<Pointer>>>>,
    peers: usize,
    address: &XorName,
    asked: Asked,
) -> SetRead {
    let mut tally = ReadTally::new(peers);
    while let Some(result) = in_flight.next().await {
        match result {
            Ok(found) => {
                tally.answer(found);
                if tally.settled() {
                    break;
                }
            }
            Err(e) => tally.answered.fail(e),
        }
    }
    tally.finish(address, asked)
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
/// close group stops as a read of it alone does. The bootstrap peers stop once
/// a quorum of them has answered and they corroborate a state; once the close
/// group has returned a state, as soon as a quorum of them has answered and
/// none names a newer one; and otherwise only once every one of them has
/// answered or failed, so that a state only a few of them hold is still found
/// when the close group has none. The read takes as long as the slower set.
async fn read_pointer<L, G, GF>(
    address: &XorName,
    close_group: L,
    bootstrap: &[(PeerId, Vec<MultiAddr>)],
    get: G,
) -> Result<Option<Pointer>>
where
    L: Future<Output = Result<Vec<(PeerId, Vec<MultiAddr>)>>>,
    G: Fn(PeerId, Vec<MultiAddr>) -> GF,
    GF: Future<Output = Result<Option<Pointer>>>,
{
    if bootstrap.is_empty() {
        let peers = close_group.await?;
        let in_flight = peers
            .iter()
            .map(|(peer, addrs)| get(*peer, addrs.clone()))
            .collect();
        return read_pointer_from(in_flight, peers.len(), address, Asked::CloseGroup)
            .await
            .outcome;
    }
    let ask = |peer: PeerId, addrs: Vec<MultiAddr>| {
        let reply = get(peer, addrs);
        async move { (peer, reply.await) }
    };
    let mut seeds = HashSet::new();
    let mut in_flight = FuturesUnordered::new();
    for (peer, addrs) in bootstrap {
        if seeds.insert(*peer) {
            in_flight.push(ask(*peer, addrs.clone()));
        }
    }
    let mut lookup = Some(Box::pin(close_group));
    // The close group's read, once the lookup has returned.
    let mut close: Option<Result<ReadTally>> = None;
    let mut members = HashSet::new();
    let mut close_waiting = 0usize;
    let mut close_done = false;
    let mut boot = ReadTally::new(seeds.len());
    let mut boot_waiting = seeds.len();
    let mut boot_done = false;
    // Bootstrap peers' replies from before the close group was known, since
    // any of them may be in it.
    let mut early = Vec::new();
    loop {
        if !close_done {
            close_done = match &close {
                Some(Ok(tally)) => tally.settled() || close_waiting == 0,
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
                    let mut tally = ReadTally::new(members.len());
                    close_waiting = members.len();
                    for (peer, reply) in early.drain(..) {
                        if members.contains(&peer) {
                            close_waiting = close_waiting.saturating_sub(1);
                            match reply {
                                Ok(found) => tally.answer(found),
                                Err(e) => tally.answered.fail(e),
                            }
                        }
                    }
                    if !tally.settled() {
                        let mut asking = HashSet::new();
                        for (peer, addrs) in peers {
                            if !seeds.contains(&peer) && asking.insert(peer) {
                                in_flight.push(ask(peer, addrs));
                            }
                        }
                    }
                    tally
                }));
            }
            Either::Right((peer, reply)) => {
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
                                Err(e) => tally.answered.fail(e),
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
    newest_pointer(close, boot.finish(address, Asked::Bootstrap))
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
        (Ok(held), Err(failure)) => {
            debug!("the bootstrap peers gave no state for a pointer: {failure}");
            if replaces(&bootstrap.seen, held.as_ref()) {
                Err(failure)
            } else {
                Ok(held)
            }
        }
        (Ok(None), Ok(Some(other))) => from_bootstrap(other),
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
/// with the same proof: a shortfall or an unreachable group, not a refusal.
fn worth_retrying(error: &Error) -> bool {
    matches!(
        error,
        Error::CloseGroupShortfall(_)
            | Error::Network(_)
            | Error::Timeout(_)
            | Error::InsufficientPeers(_)
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
) -> Option<Result<()>> {
    let ChunkMessageBody::PointerPutResponse(response) = body else {
        return None;
    };
    Some(match response {
        // `Unchanged` is success for a retry: the state the client signed is
        // exactly what the node holds.
        PointerPutResponse::Success { address, state_id }
        | PointerPutResponse::Unchanged { address, state_id } => {
            if address == expected_address && state_id == expected_state {
                Ok(())
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
        PointerPutResponse::Stale { address, state_id } => {
            Err(Error::InvalidData(if address == expected_address {
                format!(
                    "the pointer moved while this update was in flight; the network \
                     now holds state {}",
                    hex::encode(state_id)
                )
            } else {
                format!(
                    "peer refused a pointer this client did not send: address {}",
                    hex::encode(address)
                )
            }))
        }
        PointerPutResponse::PaymentRequired { message } => Err(Error::Payment(message)),
        PointerPutResponse::Error(e) => Err(Error::Protocol(format!("pointer PUT refused: {e}"))),
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

impl Client {
    /// Create a pointer at counter 0, owned by `owner`.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails, payment fails, or no storer accepts
    /// the record.
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
    /// exhausted, signing fails, payment fails, or no storer accepts it.
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
    /// Returns an error if the current record cannot be read, the counter is
    /// exhausted, or signing fails.
    pub async fn pointer_sign_update(
        &self,
        secret_key: &MlDsaSecretKey,
        owner: &MlDsaPublicKey,
        target: PointerTarget,
    ) -> Result<Pointer> {
        let address = pointer_address(owner);
        match self.pointer_get(&address).await? {
            Some(current) => current
                .update(secret_key, target)
                .map_err(|e| Error::InvalidData(format!("cannot sign pointer update: {e}"))),
            None => Pointer::create(secret_key, owner, target)
                .map_err(|e| Error::InvalidData(format!("cannot sign pointer: {e}"))),
        }
    }

    /// Pay for and store an already-signed pointer.
    ///
    /// Each call settles a payment for the state it is given. A state the
    /// network already holds is answered as stored, but the payment for it has
    /// been made either way — so a retry after a timeout costs a second quote.
    /// Read first if that matters; the node cannot tell a retry from a fresh
    /// submission before it has been paid to look.
    ///
    /// # Errors
    ///
    /// Returns an error if no peer is responsible for the address, if payment
    /// fails, or if no storer accepts the record.
    pub async fn pointer_put(&self, record: &Pointer) -> Result<XorName> {
        let address = record.address();
        let state_id = record.state_id();

        // Refuse before paying if nobody is responsible for this address.
        // There is no sense buying storage with nowhere to put it, and a
        // quorum of nothing would otherwise be satisfied by nothing — a paid
        // write reported as stored on zero peers.
        self.pointer_group(&address).await?;

        // The quote names the state; the peers that may issue it are the close
        // group around the address. One payment, one state.
        let (proof, _) = self
            .pay_for_storage_split(
                &address,
                &state_id,
                POINTER_WIRE_LEN as u64,
                DATA_TYPE_POINTER,
            )
            .await?;
        self.pointer_put_paid(record, proof).await
    }

    /// Quote a signed pointer's state for a payer outside this client, such as
    /// a browser wallet or another external signer, without paying.
    ///
    /// Pay the plan's median quote, build the proof with
    /// [`ChunkPaymentPlan::proof`], then store with [`Self::pointer_put_paid`].
    ///
    /// # Errors
    ///
    /// Returns an error if no peer is responsible for the address, or if too
    /// few acceptable quotes come back.
    pub async fn prepare_pointer_payment(&self, record: &Pointer) -> Result<ChunkPaymentPlan> {
        let address = record.address();
        // As for a wallet payment: nothing is quoted with nowhere to store it.
        self.pointer_group(&address).await?;
        self.prepare_payment_plan_split(
            &address,
            &record.state_id(),
            POINTER_WIRE_LEN as u64,
            DATA_TYPE_POINTER,
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
    /// # Errors
    ///
    /// Returns an error if no peer is responsible for the address or if too few
    /// of the close group accept the record.
    pub async fn pointer_put_paid(&self, record: &Pointer, proof: Vec<u8>) -> Result<XorName> {
        // A write that fell short is retried with the same proof, as a chunk
        // store is: peers that took it the first time answer `Unchanged`, which
        // counts, so each round only has to reach the ones that did not. A
        // refusal that says something definite — a newer state won, the
        // payment was refused, a peer acknowledged something else — is final.
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
        let wanted = write_quorum(targets.len());

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

        let answered = ask_the_group(in_flight, wanted, |()| true).await;
        if answered.count >= wanted {
            return Ok(address);
        }
        // A peer that refused — a newer state won, the payment was refused, an
        // acknowledgement named another record — is the answer, and is not
        // retried. Only a group that did not answer is a shortfall.
        if let Some(refusal) = answered.refusal {
            return Err(refusal);
        }
        if answered.count > 0 {
            return Err(Error::CloseGroupShortfall(format!(
                "pointer {} stored on {} of {wanted} close-group peers",
                hex::encode(address),
                answered.count
            )));
        }
        Err(answered.failure().unwrap_or_else(|| {
            Error::Protocol("no close-group peer accepted the pointer".to_string())
        }))
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

    /// Read the pointer at `address`, verifying it before returning it.
    ///
    /// The record is checked against the address it was asked for, so a storer
    /// cannot answer with a different owner's pointer, and the state returned
    /// must be named by at least two of the peers that return it (by the one
    /// peer, in a set of one), so no single peer of a larger set decides what
    /// the pointer says.
    ///
    /// The close group is asked, and at the same time so are the bootstrap
    /// peers nearest the address, nine at most of those the client knows by
    /// peer ID, as a second set with its own quorum and corroboration (five
    /// answers and two naming the state, of nine); a peer in both is asked
    /// once. The answer is the newer state of the two, and a state the
    /// bootstrap peers name is returned even when the close group holds none or
    /// does not answer; see `read_pointer` and `newest_pointer`. The read then
    /// takes as long as the slower of the two sets, and reports the pointer
    /// absent only once each of those bootstrap peers has answered or failed.
    /// Without such bootstrap peers only the close group is asked.
    ///
    /// # Errors
    ///
    /// Returns an error if no peer answers, if too few of the group do, or if
    /// the best state found has too few peers behind it to be the network's
    /// answer rather than one peer's, unless the bootstrap peers name a state.
    /// It also fails when too few of either set answered but those that did
    /// name a newer state than the read would otherwise return.
    pub async fn pointer_get(&self, address: &XorName) -> Result<Option<Pointer>> {
        read_pointer(
            address,
            self.pointer_group(address),
            &self.network().bootstrap_peers_near(address),
            |peer, addrs| self.send_pointer_get(*address, peer, addrs),
        )
        .await
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
        let mut seen = HashSet::new();
        let mut at = *address;

        for _ in 0..MAX_POINTER_RESOLVE_DEPTH {
            if !seen.insert(at) {
                return Err(Error::InvalidData(format!(
                    "pointer chain cycles back to {}",
                    hex::encode(at)
                )));
            }
            let record = self.pointer_get(&at).await?.ok_or_else(|| {
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
    ) -> Result<()> {
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
            assert!(judged(honest).is_ok());
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
            assert!(judged(lie).is_err(), "this must not count as stored");
        }
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
    /// short because a peer said no reports that, and is not retried.
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

    /// A read as `pointer_get` makes one, on a simulated network in paused
    /// time: the lookup returns `close_group` after `lookup` milliseconds, and
    /// each peer gives its answer from `answers`, or times out after ten
    /// seconds when it has none. Returns the read, how long it took, and how
    /// many GETs each peer was sent.
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
        )
        .await;
        (read, started.elapsed(), asked.into_inner())
    }

    fn state_of(read: Result<Option<Pointer>>) -> XorName {
        read.expect("a read").expect("a state").state_id()
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
            assert_eq!(state_of(read), held.state_id());
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
            assert_eq!(state_of(read), new.state_id());
        }
        // Agreement is per set: a newer state only one bootstrap peer names
        // does not replace the close group's.
        let mut answers = answering(1..=7, 50, || Ok(Some(old.clone())));
        answers.extend(answering(101..=108, 100, || Ok(None)));
        answers.extend(answering([109], 100, || Ok(Some(new.clone()))));
        let (read, _, _) = simulated_read(old.address(), 0, 1..=7, 101..=109, answers).await;
        assert_eq!(state_of(read), old.state_id());
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
        assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), new.state_id());
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
        assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), new.state_id());
        assert_eq!(took, Duration::from_millis(50));

        let mut answers = answering(1..=7, 50, || Ok(Some(old.clone())));
        answers.extend(answering([101], 50, || Ok(Some(new.clone()))));
        answers.extend(answering(102..=108, 50, || Ok(None)));
        answers.extend(answering([109], 2000, || Ok(Some(new.clone()))));
        let (found, took, _) = simulated_read(old.address(), 0, 1..=7, 101..=109, answers).await;
        assert_eq!(state_of(found), new.state_id());
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
            assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), held.state_id());
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
        assert_eq!(state_of(found), held.state_id());
        assert_eq!(took, Duration::from_millis(50));
        assert_eq!(asked.len(), 7);
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
}
