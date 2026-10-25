//! Transport-neutral native read policy. Adapters supply discovery, GET and sleep;
//! the engine owns ordering, fallback bounds, absence decisions and retry timing.
use futures::future::{select, Either};
use futures::{stream::FuturesUnordered, StreamExt};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    time::Duration,
};

pub(crate) const MAX_GET_FALLBACK_PEERS: usize = 20;
pub(crate) const CLOSE_GROUP_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Rounds a read waits for a peer that declined it while busy, before
/// reporting the record's holders busy. Each wait lasts until the first
/// refusal that may hide a holder ends, so with the browser's 15 s refusal
/// hold-off the waits add at most 45 s and three lookups to a read on a
/// network that is full.
const MAX_REFUSAL_WAITS: usize = 3;
const EARLY_READ_HEDGE_DELAY: Duration = Duration::from_secs(1);
/// Speculative GETs per round are bounded by this multiple of the early
/// allowance, including hints that may hold the record after stale hints used it.
const MAX_EARLY_READS_PER_ALLOWANCE: usize = 2;

pub(crate) fn is_authoritative_not_found(not_found: usize, queried: usize) -> bool {
    queried >= ant_protocol::CLOSE_GROUP_MAJORITY && not_found == queried
}

/// Discovery converges on the target, so a hint with fewer than a close group of
/// attempted peers nearer the target may still hold the record.
fn may_hold(attempted: &HashSet<[u8; 32]>, candidate: &[u8; 32], target: &[u8; 32]) -> bool {
    let distance = ant_protocol::transport::xor_distance(candidate, target);
    attempted
        .iter()
        .filter(|peer| ant_protocol::transport::xor_distance(peer, target) < distance)
        .count()
        < ant_protocol::CLOSE_GROUP_SIZE
}

/// Race one already-connected, known candidate against ordinary discovery and
/// retrieval. Both paths must verify content before returning `Some`. A cache
/// miss or transport failure is never evidence of network-wide absence; the
/// ordinary discovery/retry policy still runs. At most one extra GET is active.
pub(crate) async fn race_cached_read<T, E>(
    cached: Option<impl Future<Output = Result<Option<T>, E>>>,
    discovered: impl Future<Output = Result<Option<T>, E>>,
    retryable: impl Fn(&E) -> bool,
) -> Result<Option<T>, E> {
    let Some(cached) = cached else {
        return discovered.await;
    };
    let remaining = match select(Box::pin(cached), Box::pin(discovered)).await {
        Either::Left((result, remaining)) => match result {
            Ok(Some(value)) => return Ok(Some(value)),
            Err(error) if !retryable(&error) => return Err(error),
            _ => remaining.await,
        },
        Either::Right((result, remaining)) => match result {
            Ok(Some(value)) => return Ok(Some(value)),
            Err(error) if !retryable(&error) => return Err(error),
            _ => remaining.await,
        },
    };
    match remaining {
        Err(error) if retryable(&error) => Ok(None),
        result => result,
    }
}

/// Discovery results need not include all reachable storage holders.
pub(crate) struct ReadCandidates<P> {
    pub closest: Vec<P>,
    pub known: Vec<P>,
}

/// Keep primary peers first, ordered by XOR distance, then the bootstrap peers
/// the read asks, then bounded, deduplicated known peers, each ordered the same
/// way. Discovery failure suppression must not filter the latter two. Every
/// bootstrap peer given is kept, so a round establishes absence only after all
/// of them have answered: a read is given at most the nine nearest the record
/// its lookup leaves among the nearest ([`crate::data::network::seeds_for_read`]).
pub(crate) fn read_targets<P: Clone>(
    candidates: ReadCandidates<P>,
    bootstrap: &[P],
    target: &[u8; 32],
    key: impl Fn(&P) -> [u8; 32],
) -> Vec<P> {
    let mut primary = candidates.closest;
    let mut bootstrap = bootstrap.to_vec();
    let mut known = candidates.known;
    primary.sort_by_key(|p| ant_protocol::transport::xor_distance(&key(p), target));
    bootstrap.sort_by_key(|p| ant_protocol::transport::xor_distance(&key(p), target));
    known.sort_by_key(|p| ant_protocol::transport::xor_distance(&key(p), target));
    let mut seen = HashSet::new();
    primary.retain(|p| seen.insert(key(p)));
    primary.extend(bootstrap.into_iter().filter(|p| seen.insert(key(p))));
    primary.extend(
        known
            .into_iter()
            .filter(|p| seen.insert(key(p)))
            .take(MAX_GET_FALLBACK_PEERS),
    );
    primary
}

/// What one GET's result means for a read: a verified record or a fatal error
/// ends it, a miss counts towards absence, and a retryable failure moves on.
fn conclusive<T, E>(
    id: [u8; 32],
    result: Result<Option<T>, E>,
    not_found: &std::sync::Mutex<HashSet<[u8; 32]>>,
    retryable: impl Fn(&E) -> bool,
) -> Option<Result<Option<T>, E>> {
    match result {
        Ok(Some(value)) => Some(Ok(Some(value))),
        Ok(None) => {
            not_found
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id);
            None
        }
        Err(error) if !retryable(&error) => Some(Err(error)),
        Err(_) => None,
    }
}

/// Discover and read concurrently. Early hints are never absence votes or
/// close-group authority. A stalled early GET may race one other candidate after
/// a delay, on both native and WASM. At most two GETs run, including after discovery.
/// A peer is queried at most once per round, and only the completed final candidate
/// set can establish absence.
///
/// `bootstrap` peers, the nine nearest the target at most
/// ([`crate::data::network::bootstrap_read_peers`]), are not read before
/// discovery answers, except as discovery offers them, a connected one
/// included. Then the read asks those that discovery's view leaves among the
/// nine nearest the target, or every one when discovery found no peer
/// ([`crate::data::network::seeds_for_read`]), in a lane of their own, nearest
/// first, one at a time, alongside the ordinary path. In the final candidate
/// set they follow the closest peers. With none, reads use discovery alone.
///
/// `refused` lists peers the adapter skips for now because they declined a
/// session while busy, each with the time until it is tried again. While one
/// of them may hold the record, a round that finds nothing proves nothing:
/// the read waits for the first of them to return, up to `MAX_REFUSAL_WAITS`
/// times, and then fails with `busy()` rather than report the record absent.
#[allow(clippy::too_many_arguments)] // Adapters supply each hook; the engine owns how they combine.
pub(crate) async fn retrieve_progressive<P, T, E, D, DF, G, GF, S, SF>(
    target: [u8; 32],
    early_limit: usize,
    bootstrap: Vec<P>,
    discover: D,
    key: impl Fn(&P) -> [u8; 32],
    get: G,
    retryable: impl Fn(&E) -> bool,
    refused: impl Fn() -> Vec<([u8; 32], Duration)>,
    busy: impl FnOnce() -> E,
    sleep: S,
) -> Result<Option<T>, E>
where
    P: Clone,
    D: Fn(tokio::sync::watch::Sender<Vec<P>>) -> DF,
    DF: Future<Output = ReadCandidates<P>>,
    G: Fn(P, bool) -> GF,
    GF: Future<Output = Result<Option<T>, E>>,
    S: Fn(Duration) -> SF,
    SF: Future<Output = ()>,
{
    let allowance = early_limit.min(MAX_GET_FALLBACK_PEERS);
    let max_early_reads = allowance * MAX_EARLY_READS_PER_ALLOWANCE;
    let mut bootstrap = bootstrap;
    bootstrap.sort_by_key(|p| ant_protocol::transport::xor_distance(&key(p), &target));
    let mut listed = HashSet::new();
    bootstrap.retain(|p| listed.insert(key(p)));
    let mut delay = None;
    let mut retried = false;
    let mut refusal_waits = 0;
    loop {
        if let Some(delay) = delay {
            sleep(delay).await;
        }
        let refused_at_start = refused();
        let (sender, mut updates) = tokio::sync::watch::channel(Vec::new());
        let mut discovery = Box::pin(discover(sender));
        let mut attempted = HashSet::new();
        let not_found = std::sync::Mutex::new(HashSet::new());
        let mut active = FuturesUnordered::new();
        let early_get = |peer: P| {
            let id = key(&peer);
            let future = get(peer, true);
            async move { (id, future.await) }
        };
        let mut hedge_timer = None;
        let mut hedge_ready = false;
        let mut updates_open = true;
        let candidates = loop {
            if (active.is_empty() || (active.len() == 1 && hedge_ready))
                && attempted.len() < max_early_reads
            {
                // Stale hints can use the allowance before discovery reaches the
                // holders; hints converging on the target remain eligible.
                let within_allowance = attempted.len() < allowance;
                let next = updates
                    .borrow_and_update()
                    .iter()
                    .filter(|peer| !attempted.contains(&key(peer)))
                    .min_by_key(|peer| ant_protocol::transport::xor_distance(&key(peer), &target))
                    .filter(|peer| within_allowance || may_hold(&attempted, &key(peer), &target))
                    .cloned();
                if let Some(peer) = next {
                    attempted.insert(key(&peer));
                    if active.is_empty() {
                        hedge_ready = false;
                        hedge_timer = Some(Box::pin(sleep(EARLY_READ_HEDGE_DELAY)));
                    }
                    active.push(early_get(peer));
                }
            }
            let event = {
                let changed = async {
                    if updates_open {
                        updates.changed().await.is_ok()
                    } else {
                        futures::future::pending().await
                    }
                };
                let read = async {
                    match active.next().await {
                        Some(read) => read,
                        None => futures::future::pending().await,
                    }
                };
                let hedge = async {
                    match &mut hedge_timer {
                        Some(timer) => timer.await,
                        None => futures::future::pending().await,
                    }
                };
                match select(
                    discovery.as_mut(),
                    Box::pin(select(
                        Box::pin(read),
                        Box::pin(select(Box::pin(changed), Box::pin(hedge))),
                    )),
                )
                .await
                {
                    Either::Left((candidates, _)) => Either::Left(candidates),
                    Either::Right((event, _)) => Either::Right(match event {
                        Either::Left((result, _)) => Either::Left(result),
                        Either::Right((event, _)) => Either::Right(match event {
                            Either::Left((open, _)) => Some(open),
                            Either::Right(_) => None,
                        }),
                    }),
                }
            };
            match event {
                Either::Left(candidates) => break candidates,
                Either::Right(Either::Right(Some(open))) => updates_open = open,
                Either::Right(Either::Right(None)) => {
                    hedge_ready = true;
                    hedge_timer = None;
                }
                Either::Right(Either::Left((id, result))) => {
                    if let Some(read) = conclusive(id, result, &not_found, &retryable) {
                        return read;
                    }
                }
            }
        };
        // The bootstrap peers this round asks: those discovery's view, what it
        // found and offered, leaves among the nearest; every one when it found
        // no peer.
        let seeds = if candidates.closest.is_empty() {
            bootstrap.clone()
        } else {
            crate::data::network::seeds_for_read(
                &bootstrap,
                candidates
                    .closest
                    .iter()
                    .chain(updates.borrow().iter())
                    .map(&key),
                &target,
                &key,
            )
        };
        let peers = read_targets(candidates, &seeds, &target, &key);
        let final_ids = peers.iter().map(&key).collect::<HashSet<_>>();
        // Discovery may finish with two early reads still active. Each one that
        // retires frees its slot, for the ordinary path first and then the
        // bootstrap lane; never create a third wire GET.
        let (ordinary_slot, ordinary_turn) = futures::channel::oneshot::channel();
        let (bootstrap_slot, bootstrap_turn) = futures::channel::oneshot::channel();
        let mut slots = [ordinary_slot, bootstrap_slot].into_iter();
        for slot in slots.by_ref().take(2usize.saturating_sub(active.len())) {
            let _ = slot.send(());
        }
        let attempted = std::sync::Mutex::new(attempted);
        // Claims `peer` for one lane, once per round.
        let claim = |peer: &P| {
            attempted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key(peer))
        };
        let pending_early = (!active.is_empty()).then(|| {
            let not_found = &not_found;
            let retryable = &retryable;
            async move {
                while let Some((id, result)) = active.next().await {
                    if let Some(slot) = slots.next() {
                        let _ = slot.send(());
                    }
                    if let Some(read) = conclusive(id, result, not_found, retryable) {
                        return read;
                    }
                }
                Ok(None)
            }
        });
        let ordinary = async {
            let _ = ordinary_turn.await;
            for peer in peers {
                if !claim(&peer) {
                    continue;
                }
                let id = key(&peer);
                if let Some(read) = conclusive(id, get(peer, false).await, &not_found, &retryable) {
                    return read;
                }
            }
            Ok(None)
        };
        // The bootstrap peers asked and not yet claimed, alongside the ordinary path.
        let bootstrap_lane = async {
            let untried = |peer: &P| {
                !attempted
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&key(peer))
            };
            if !seeds.iter().any(untried) {
                return Ok(None);
            }
            let _ = bootstrap_turn.await;
            for peer in &seeds {
                if !claim(peer) {
                    continue;
                }
                let id = key(peer);
                let result = get(peer.clone(), false).await;
                if let Some(read) = conclusive(id, result, &not_found, &retryable) {
                    return read;
                }
            }
            Ok(None)
        };
        let lanes = race_cached_read(Some(bootstrap_lane), ordinary, &retryable);
        if let Some(value) = race_cached_read(pending_early, lanes, &retryable).await? {
            return Ok(Some(value));
        }
        let refused_now = refused().into_iter().collect::<HashMap<_, _>>();
        let (absent, refusal) = {
            let misses = not_found.lock().unwrap_or_else(|e| e.into_inner());
            let absent = is_authoritative_not_found(
                final_ids.intersection(&misses).count(),
                final_ids.len(),
            );
            // A refused peer stays out of discovery and reads, so this round
            // may never have asked it. It cannot hold the record once it, or a
            // close group of nearer peers, answered NotFound. A refusal that
            // ended during the round is ready now.
            let refusal = refused_at_start
                .iter()
                .map(|(peer, _)| peer)
                .chain(refused_now.keys())
                .filter(|peer| !misses.contains(*peer) && may_hold(&misses, peer, &target))
                .map(|peer| refused_now.get(peer).copied().unwrap_or_default())
                .min();
            (absent, refusal)
        };
        delay = Some(match refusal {
            Some(_) if refusal_waits == MAX_REFUSAL_WAITS => return Err(busy()),
            Some(remaining) => {
                refusal_waits += 1;
                remaining.max(CLOSE_GROUP_RETRY_DELAY)
            }
            None if absent || retried => return Ok(None),
            None => {
                retried = true;
                CLOSE_GROUP_RETRY_DELAY
            }
        });
    }
}

#[cfg(test)]
async fn retrieve<P: Clone, T, E, D, DF, G, GF, S, SF>(
    target: [u8; 32],
    discover: D,
    key: impl Fn(&P) -> [u8; 32],
    get: G,
    retryable: impl Fn(&E) -> bool,
    sleep: S,
) -> Result<Option<T>, E>
where
    D: Fn() -> DF,
    DF: Future<Output = ReadCandidates<P>>,
    G: Fn(P) -> GF,
    GF: Future<Output = Result<Option<T>, E>>,
    S: Fn(Duration) -> SF,
    SF: Future<Output = ()>,
{
    retrieve_progressive(
        target,
        0,
        Vec::new(),
        |_| discover(),
        key,
        |peer, _| get(peer),
        retryable,
        Vec::new,
        || unreachable!("no peer is refused"),
        sleep,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    fn peer(id: u8) -> [u8; 32] {
        [id; 32]
    }

    #[derive(Debug, PartialEq)]
    enum ReadError {
        Transport,
        Integrity,
    }

    /// GETs on a simulated network, for reads in paused time: each takes
    /// `latency`, or waits out a ten-second timeout for a silent peer. Keeps
    /// every GET asked, and the most that were in flight at once.
    #[derive(Default)]
    struct Simulated {
        gets: RefCell<Vec<([u8; 32], bool)>>,
        in_flight: Cell<usize>,
        most: Cell<usize>,
    }

    /// One GET in flight, until it answers or is dropped.
    struct InFlight<'a>(&'a Cell<usize>);

    impl Drop for InFlight<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() - 1);
        }
    }

    impl Simulated {
        fn get(
            &self,
            p: [u8; 32],
            early: bool,
            latency: Duration,
            silent: bool,
            holds: bool,
        ) -> impl Future<Output = Result<Option<u32>, ReadError>> + '_ {
            self.gets.borrow_mut().push((p, early));
            async move {
                self.in_flight.set(self.in_flight.get() + 1);
                self.most.set(self.most.get().max(self.in_flight.get()));
                let _in_flight = InFlight(&self.in_flight);
                if silent {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Err(ReadError::Transport)
                } else {
                    tokio::time::sleep(latency).await;
                    Ok(holds.then_some(42))
                }
            }
        }

        fn asked(&self) -> Vec<[u8; 32]> {
            let mut asked: Vec<_> = self.gets.borrow().iter().map(|(p, _)| *p).collect();
            asked.sort_unstable();
            asked
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_early_read_can_race_a_new_hint_before_discovery_finishes() {
        let gets = RefCell::new(Vec::new());
        let start = tokio::time::Instant::now();
        let read = retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |updates| async move {
                updates.send_replace(vec![peer(1)]);
                tokio::time::sleep(Duration::from_millis(500)).await;
                updates.send_replace(vec![peer(1), peer(2)]);
                futures::future::pending().await
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                async move {
                    if p == peer(1) {
                        futures::future::pending().await
                    } else {
                        Ok::<_, ReadError>(Some(42))
                    }
                }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        );
        let result = tokio::time::timeout(Duration::from_secs(2), read)
            .await
            .expect("hedged read stalled");
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(start.elapsed(), EARLY_READ_HEDGE_DELAY);
        assert_eq!(*gets.borrow(), vec![(peer(1), true), (peer(2), true)]);
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_completion_does_not_add_a_third_get_to_two_early_reads() {
        use futures::FutureExt;
        let (found, found_rx) = futures::channel::oneshot::channel();
        let found = RefCell::new(Some(found));
        let found_rx = RefCell::new(Some(found_rx));
        let (release, release_rx) = futures::channel::oneshot::channel();
        let release_rx = RefCell::new(Some(release_rx));
        let gets = RefCell::new(Vec::new());
        let future = retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |updates| {
                let found_rx = found_rx.borrow_mut().take().unwrap();
                async move {
                    updates.send_replace(vec![peer(1), peer(2)]);
                    found_rx.await.unwrap();
                    ReadCandidates {
                        closest: vec![peer(1), peer(2), peer(3)],
                        known: vec![],
                    }
                }
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                let release_rx = if p == peer(1) {
                    release_rx.borrow_mut().take()
                } else {
                    None
                };
                let found = &found;
                async move {
                    if let Some(release_rx) = release_rx {
                        release_rx.await.unwrap();
                        Ok::<_, ReadError>(None)
                    } else if p == peer(2) {
                        found.borrow_mut().take().unwrap().send(()).unwrap();
                        futures::future::pending().await
                    } else {
                        Ok(Some(42))
                    }
                }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        );
        futures::pin_mut!(future);
        assert!(future.as_mut().now_or_never().is_none());
        tokio::time::advance(EARLY_READ_HEDGE_DELAY).await;
        assert!(future.as_mut().now_or_never().is_none());
        assert_eq!(*gets.borrow(), vec![(peer(1), true), (peer(2), true)]);
        release.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), future)
                .await
                .expect("ordinary read stalled"),
            Ok(Some(42))
        );
        assert_eq!(
            *gets.borrow(),
            vec![(peer(1), true), (peer(2), true), (peer(3), false)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_hint_near_the_target_is_read_after_stale_hints_use_the_allowance() {
        let allowance = ant_protocol::CLOSE_GROUP_SIZE;
        let gets = RefCell::new(Vec::new());
        let read = retrieve_progressive(
            peer(0),
            allowance,
            Vec::new(),
            |updates| async move {
                updates.send_replace((200..).take(allowance).map(peer).collect());
                tokio::time::sleep(Duration::from_secs(10)).await;
                updates.send_replace(vec![peer(1)]);
                futures::future::pending().await
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                async move { Ok::<_, ReadError>((p == peer(1)).then_some(42)) }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        );
        let result = tokio::time::timeout(Duration::from_secs(20), read)
            .await
            .expect("the read waited for discovery to finish");
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(gets.borrow().len(), allowance + 1);
        assert_eq!(gets.borrow().last(), Some(&(peer(1), true)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_far_hint_is_not_read_after_the_allowance_is_used() {
        let allowance = ant_protocol::CLOSE_GROUP_SIZE;
        let gets = RefCell::new(Vec::new());
        let read = retrieve_progressive(
            peer(0),
            allowance,
            Vec::new(),
            |updates| async move {
                // A close group of attempted peers is nearer than the late hint.
                updates.send_replace((1..).take(allowance).map(peer).collect());
                tokio::time::sleep(Duration::from_secs(10)).await;
                updates.send_replace(vec![peer(200)]);
                tokio::time::sleep(Duration::from_secs(10)).await;
                ReadCandidates {
                    closest: vec![peer(100)],
                    known: vec![],
                }
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                async move { Ok::<_, ReadError>((p == peer(100)).then_some(42)) }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        );
        assert_eq!(read.await, Ok(Some(42)));
        assert!(!gets.borrow().contains(&(peer(200), true)));
        assert_eq!(gets.borrow().last(), Some(&(peer(100), false)));
    }

    #[tokio::test(start_paused = true)]
    async fn speculative_reads_stop_at_twice_the_allowance() {
        let gets = RefCell::new(Vec::new());
        let read = retrieve_progressive(
            peer(0),
            1,
            Vec::new(),
            |updates| async move {
                updates.send_replace(vec![peer(200)]);
                tokio::time::sleep(Duration::from_secs(1)).await;
                // Each of these may hold the record, but only one fits the bound.
                updates.send_replace(vec![peer(1), peer(2), peer(3)]);
                tokio::time::sleep(Duration::from_secs(1)).await;
                ReadCandidates {
                    closest: vec![peer(1), peer(2), peer(3)],
                    known: vec![],
                }
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                async move { Ok::<_, ReadError>((p == peer(3)).then_some(42)) }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        );
        assert_eq!(read.await, Ok(Some(42)));
        assert_eq!(
            *gets.borrow(),
            vec![
                (peer(200), true),
                (peer(1), true),
                (peer(2), false),
                (peer(3), false)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn integrity_failure_from_a_hedged_read_remains_fatal() {
        let read = retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |updates| async move {
                updates.send_replace(vec![peer(1), peer(2)]);
                futures::future::pending().await
            },
            |p| *p,
            |p, _| async move {
                if p == peer(1) {
                    futures::future::pending().await
                } else {
                    Err::<Option<()>, _>(ReadError::Integrity)
                }
            },
            |error| *error == ReadError::Transport,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        );
        let result = tokio::time::timeout(Duration::from_secs(2), read)
            .await
            .expect("integrity failure was not returned");
        assert_eq!(result, Err(ReadError::Integrity));
    }

    #[test]
    fn progressive_verified_read_finishes_before_discovery() {
        let result = futures::executor::block_on(retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |updates| async move {
                updates.send_replace(vec![peer(1)]);
                futures::future::pending().await
            },
            |p| *p,
            |_, early| async move {
                assert!(early);
                Ok::<_, ReadError>(Some(42))
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        ));
        assert_eq!(result, Ok(Some(42)));
    }

    #[test]
    fn early_misses_cannot_end_incomplete_discovery() {
        use futures::FutureExt;
        let gets = Cell::new(0);
        let result = retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |updates| async move {
                updates.send_replace((1..=7).map(peer).collect());
                futures::future::pending().await
            },
            |p| *p,
            |_, early| {
                assert!(early);
                gets.set(gets.get() + 1);
                async { Ok::<Option<()>, ReadError>(None) }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        )
        .now_or_never();
        assert!(result.is_none());
        assert_eq!(gets.get(), 7);
    }

    #[test]
    fn slow_early_get_is_deduplicated_and_does_not_block_another_holder() {
        let (send, receive) = futures::channel::oneshot::channel();
        let send = RefCell::new(Some(send));
        let receive = RefCell::new(Some(receive));
        let gets = RefCell::new(Vec::new());
        let result = futures::executor::block_on(retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |updates| {
                let receive = receive.borrow_mut().take().unwrap();
                async move {
                    updates.send_replace(vec![peer(1)]);
                    receive.await.unwrap();
                    ReadCandidates {
                        closest: vec![peer(1), peer(2)],
                        known: vec![],
                    }
                }
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                let send = &send;
                async move {
                    if p == peer(1) {
                        send.borrow_mut().take().unwrap().send(()).unwrap();
                        futures::future::pending().await
                    } else {
                        Ok::<_, ReadError>(Some(42))
                    }
                }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        ));
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(*gets.borrow(), vec![(peer(1), true), (peer(2), false)]);
    }

    #[test]
    fn progressive_early_budget_preserves_ordinary_fallback_and_absence() {
        let (send, receive) = futures::channel::oneshot::channel();
        let send = RefCell::new(Some(send));
        let receive = RefCell::new(Some(receive));
        let gets = RefCell::new(Vec::new());
        let result = futures::executor::block_on(retrieve_progressive(
            peer(0),
            2,
            Vec::new(),
            |updates| {
                let receive = receive.borrow_mut().take().unwrap();
                async move {
                    updates.send_replace((1..=7).map(peer).collect());
                    receive.await.unwrap();
                    ReadCandidates {
                        closest: (1..=7).map(peer).collect(),
                        known: vec![],
                    }
                }
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                if p == peer(2) {
                    send.borrow_mut().take().unwrap().send(()).unwrap();
                }
                async { Ok::<Option<()>, ReadError>(None) }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        ));
        assert_eq!(result, Ok(None));
        let gets = gets.borrow();
        assert_eq!(gets.len(), 7);
        assert_eq!(gets.iter().filter(|(_, early)| *early).count(), 2);
        assert_eq!(gets.iter().map(|(p, _)| p).collect::<HashSet<_>>().len(), 7);
    }

    #[test]
    fn early_integrity_errors_remain_fatal_before_discovery() {
        let result = futures::executor::block_on(retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |updates| async move {
                updates.send_replace(vec![peer(1)]);
                futures::future::pending().await
            },
            |p| *p,
            |_, _| async { Err::<Option<()>, _>(ReadError::Integrity) },
            |error| *error == ReadError::Transport,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        ));
        assert_eq!(result, Err(ReadError::Integrity));
    }

    #[test]
    fn cached_verified_content_does_not_wait_for_discovery() {
        let result = futures::executor::block_on(race_cached_read(
            Some(async { Ok::<_, ReadError>(Some(42)) }),
            futures::future::pending(),
            |_| false,
        ));
        assert_eq!(result, Ok(Some(42)));
    }

    #[test]
    fn cached_misses_and_transport_errors_preserve_discovery() {
        for cached in [Ok(None), Err(ReadError::Transport)] {
            let result = futures::executor::block_on(race_cached_read(
                Some(async { cached }),
                async { Ok(Some(42)) },
                |error| *error == ReadError::Transport,
            ));
            assert_eq!(result, Ok(Some(42)));
        }
    }

    #[test]
    fn cached_integrity_errors_remain_fatal() {
        let result = futures::executor::block_on(race_cached_read(
            Some(async { Err::<Option<()>, _>(ReadError::Integrity) }),
            futures::future::pending(),
            |error| *error == ReadError::Transport,
        ));
        assert_eq!(result, Err(ReadError::Integrity));
    }

    #[test]
    fn an_unresponsive_cached_peer_does_not_delay_a_discovered_holder() {
        let result = futures::executor::block_on(race_cached_read(
            Some(futures::future::pending()),
            async { Ok::<_, ReadError>(Some(42)) },
            |_| false,
        ));
        assert_eq!(result, Ok(Some(42)));
    }

    #[test]
    fn discovered_absence_does_not_discard_a_late_cached_holder() {
        let (send, receive) = futures::channel::oneshot::channel();
        let result = futures::executor::block_on(race_cached_read(
            Some(async { Ok::<_, ReadError>(Some(receive.await.unwrap())) }),
            async {
                send.send(42).unwrap();
                Ok(None)
            },
            |_| false,
        ));
        assert_eq!(result, Ok(Some(42)));
    }

    #[test]
    fn cached_miss_is_not_an_authoritative_not_found_vote() {
        let rounds = Cell::new(0);
        let discovered = retrieve(
            peer(0),
            || {
                rounds.set(rounds.get() + 1);
                async {
                    ReadCandidates {
                        closest: vec![peer(1)],
                        known: vec![],
                    }
                }
            },
            |p| *p,
            |_| async { Ok::<Option<()>, ReadError>(None) },
            |_| true,
            |_| async {},
        );
        let result = futures::executor::block_on(race_cached_read(
            Some(async { Ok(None) }),
            discovered,
            |_| true,
        ));
        assert_eq!(result, Ok(None));
        assert_eq!(rounds.get(), 2);
    }

    #[test]
    fn fallback_is_sorted_deduplicated_and_bounded() {
        let targets = read_targets(
            ReadCandidates {
                closest: vec![peer(3), peer(1), peer(1)],
                known: (0..30).rev().map(peer).collect(),
            },
            &[],
            &peer(0),
            |p| *p,
        );
        assert_eq!(&targets[..4], &[peer(1), peer(3), peer(0), peer(2)]);
        assert_eq!(targets.len(), 22);
        assert_eq!(targets.iter().collect::<HashSet<_>>().len(), 22);
    }

    #[test]
    fn bootstrap_peers_follow_the_closest_and_are_all_kept() {
        // The nine bootstrap peers a read is given at most, one of which is
        // also among the closest.
        let bootstrap: Vec<_> = (40..48).rev().chain([1]).map(peer).collect();
        assert_eq!(
            bootstrap.len(),
            crate::data::network::MAX_BOOTSTRAP_READ_PEERS
        );
        let targets = read_targets(
            ReadCandidates {
                closest: vec![peer(3), peer(1)],
                known: (0..30).chain(40..45).rev().map(peer).collect(),
            },
            &bootstrap,
            &peer(0),
            |p| *p,
        );
        assert_eq!(&targets[..2], &[peer(1), peer(3)]);
        // Every other bootstrap peer, nearest first, ahead of the known peers.
        assert_eq!(&targets[2..10], &(40..48).map(peer).collect::<Vec<_>>()[..]);
        // Then the known peers not already listed, bounded as before.
        assert_eq!(&targets[10..13], &[peer(0), peer(2), peer(4)]);
        assert_eq!(targets.len(), 10 + MAX_GET_FALLBACK_PEERS);
        assert_eq!(targets.iter().collect::<HashSet<_>>().len(), targets.len());
    }

    #[test]
    fn bootstrap_peers_are_not_read_before_discovery_answers() {
        use futures::FutureExt;
        let gets = Cell::new(0);
        // Discovery never answers and offers nothing: no seed is asked.
        let result = retrieve_progressive(
            peer(0),
            7,
            vec![peer(9), peer(3)],
            |_| futures::future::pending::<ReadCandidates<[u8; 32]>>(),
            |p| *p,
            |_, _| {
                gets.set(gets.get() + 1);
                async { Ok::<_, ReadError>(Some(42)) }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        )
        .now_or_never();
        assert!(result.is_none());
        assert_eq!(gets.get(), 0);
    }

    #[test]
    fn without_bootstrap_peers_nothing_is_read_before_discovery_offers_hints() {
        use futures::FutureExt;
        let gets = Cell::new(0);
        let result = retrieve_progressive(
            peer(0),
            7,
            Vec::new(),
            |_| futures::future::pending::<ReadCandidates<[u8; 32]>>(),
            |p| *p,
            |_, _| {
                gets.set(gets.get() + 1);
                async { Ok::<Option<()>, ReadError>(None) }
            },
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        )
        .now_or_never();
        assert!(result.is_none());
        assert_eq!(gets.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bootstrap_holder_is_read_while_the_close_group_is_silent() {
        let close_group = || (1..=7).map(peer);
        let gets = RefCell::new(Vec::new());
        let start = tokio::time::Instant::now();
        let result = retrieve_progressive(
            peer(0),
            MAX_GET_FALLBACK_PEERS,
            vec![peer(100)],
            |_| async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                ReadCandidates {
                    closest: close_group().collect(),
                    known: vec![],
                }
            },
            |p| *p,
            |p, early| {
                gets.borrow_mut().push((p, early));
                let silent = close_group().any(|member| member == p);
                async move {
                    if silent {
                        // As a GET that never gets an answer: a timeout.
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        Err(ReadError::Transport)
                    } else {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Ok(Some(42))
                    }
                }
            },
            |error| *error == ReadError::Transport,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        )
        .await;
        assert_eq!(result, Ok(Some(42)));
        // Asked in its own lane once discovery answers, the eighth nearest
        // peer in discovery's view, it answers before any close-group GET
        // times out.
        assert_eq!(start.elapsed(), Duration::from_millis(2500));
        let mut asked = gets.borrow().clone();
        asked.sort_unstable();
        assert_eq!(asked, vec![(peer(1), false), (peer(100), false)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bootstrap_holder_is_read_alongside_the_ordinary_path() {
        // The close group answers "not found", and the farther of two
        // bootstrap peers holds the record. No early reads on hints.
        let latency = Duration::from_millis(100);
        let net = Simulated::default();
        let start = tokio::time::Instant::now();
        let result = retrieve_progressive(
            peer(0),
            0,
            vec![peer(100), peer(50)],
            |_| async {
                ReadCandidates {
                    closest: (1..=7).map(peer).collect(),
                    known: vec![peer(8)],
                }
            },
            |p| *p,
            |p, early| net.get(p, early, latency, false, p == peer(100)),
            |_| true,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        )
        .await;
        assert_eq!(result, Ok(Some(42)));
        // The bootstrap lane asks the nearer one, then the holder, while the
        // ordinary path asks the close group: two round trips, not nine.
        assert_eq!(start.elapsed(), 2 * latency);
        assert_eq!(
            net.asked(),
            [1, 2, 50, 100].map(peer).to_vec(),
            "each peer at most once"
        );
        assert_eq!(net.most.get(), 2);
    }

    /// Reads `peer(0)` with the nine bootstrap peers 101 to 109, nearest the
    /// target first, after discovery finds `closest`, each answering "not
    /// found" unless it is `holder`. Returns the read and every peer asked.
    fn read_with_nine_seeds(
        closest: Vec<[u8; 32]>,
        holder: Option<u8>,
    ) -> (Result<Option<u32>, ReadError>, Vec<u8>) {
        let gets = RefCell::new(Vec::new());
        let result = futures::executor::block_on(retrieve_progressive(
            peer(0),
            0,
            (101..=109).rev().map(peer).collect(),
            |_| {
                let closest = closest.clone();
                async move {
                    ReadCandidates {
                        closest,
                        known: vec![],
                    }
                }
            },
            |p| *p,
            |p, _| {
                gets.borrow_mut().push(p[0]);
                async move { Ok::<_, ReadError>((Some(p[0]) == holder).then_some(42)) }
            },
            |error| *error == ReadError::Transport,
            Vec::new,
            || unreachable!("no peer is refused"),
            |_| async {},
        ));
        (result, gets.into_inner())
    }

    #[test]
    fn seeds_the_lookup_leaves_outside_the_nine_nearest_are_not_asked() {
        // Seven peers nearer than every seed: only the two nearest seeds are
        // among the nine nearest of what the read knows. A record only a
        // farther seed holds is not looked for there.
        for holder in [Some(103), Some(109), None] {
            let (result, mut asked) = read_with_nine_seeds((1..=7).map(peer).collect(), holder);
            assert_eq!(result, Ok(None), "holder {holder:?}");
            asked.sort_unstable();
            asked.dedup();
            assert_eq!(asked, (1..=7).chain([101, 102]).collect::<Vec<u8>>());
        }
        // The second nearest seed holds it: read.
        let (result, asked) = read_with_nine_seeds((1..=7).map(peer).collect(), Some(102));
        assert_eq!(result, Ok(Some(42)));
        assert!(asked.iter().all(|&n| n <= 102), "{asked:?}");
    }

    #[test]
    fn every_seed_is_asked_when_discovery_finds_no_peer() {
        let (result, asked) = read_with_nine_seeds(Vec::new(), Some(109));
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(asked, (101..=109).collect::<Vec<u8>>(), "nearest first");
        // Nobody holds it: every seed is asked before the record is absent.
        let (result, mut asked) = read_with_nine_seeds(Vec::new(), None);
        assert_eq!(result, Ok(None));
        asked.sort_unstable();
        asked.dedup();
        assert_eq!(asked, (101..=109).collect::<Vec<u8>>());
    }

    #[test]
    fn a_thin_lookup_leaves_more_seeds_among_the_nearest() {
        // Discovery found two peers: seven seeds are among the nine nearest.
        let (result, mut asked) = read_with_nine_seeds(vec![peer(1), peer(2)], None);
        assert_eq!(result, Ok(None));
        asked.sort_unstable();
        asked.dedup();
        assert_eq!(
            asked,
            [1, 2].into_iter().chain(101..=107).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn absence_is_established_only_once_every_bootstrap_peer_asked_has_answered() {
        // A bootstrap peer that fails to answer keeps a round from establishing
        // absence, like any final candidate. When every one answers, one round
        // is enough.
        for (failing, expected_rounds) in [(None, 1), (Some(peer(100)), 2)] {
            let rounds = Cell::new(0);
            let gets = RefCell::new(Vec::new());
            let result = futures::executor::block_on(retrieve_progressive(
                peer(0),
                0,
                vec![peer(50), peer(100)],
                |_| {
                    rounds.set(rounds.get() + 1);
                    async {
                        ReadCandidates {
                            closest: (1..=7).map(peer).collect(),
                            known: vec![],
                        }
                    }
                },
                |p| *p,
                |p, _| {
                    gets.borrow_mut().push(p);
                    async move {
                        if Some(p) == failing {
                            Err(ReadError::Transport)
                        } else {
                            Ok::<Option<()>, _>(None)
                        }
                    }
                },
                |error| *error == ReadError::Transport,
                Vec::new,
                || unreachable!("no peer is refused"),
                |_| async {},
            ));
            assert_eq!(result, Ok(None));
            assert_eq!(rounds.get(), expected_rounds);
            // Each round asks the close group and both bootstrap peers, the
            // eighth and ninth nearest of what it knows, once.
            let mut asked = gets.borrow().clone();
            asked.sort_unstable();
            let mut expected = (1..=7)
                .chain([50, 100])
                .map(peer)
                .collect::<Vec<_>>()
                .repeat(expected_rounds);
            expected.sort_unstable();
            assert_eq!(asked, expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_connected_holder_is_read_at_once_whatever_the_bootstrap_peers() {
        // The bootstrap peer nearest the record never answers. A connected
        // holder offered at once is read at once, and the seed is never asked
        // before discovery answers.
        let latency = Duration::from_millis(50);
        let net = Simulated::default();
        let start = tokio::time::Instant::now();
        let result = retrieve_progressive(
            peer(0),
            MAX_GET_FALLBACK_PEERS,
            vec![peer(1)],
            |updates| async move {
                updates.send_replace(vec![peer(9)]);
                futures::future::pending().await
            },
            |p| *p,
            |p, early| net.get(p, early, latency, p == peer(1), p == peer(9)),
            |error| *error == ReadError::Transport,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        )
        .await;
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(start.elapsed(), latency);
        assert_eq!(*net.gets.borrow(), vec![(peer(9), true)]);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_bootstrap_peers_leave_a_slot_to_the_ordinary_path() {
        // Both bootstrap peers are nearest the record and never answer, and
        // discovery finds the holder after a second and a half.
        let latency = Duration::from_millis(50);
        let net = Simulated::default();
        let start = tokio::time::Instant::now();
        let result = retrieve_progressive(
            peer(0),
            MAX_GET_FALLBACK_PEERS,
            vec![peer(1), peer(2)],
            |_| async {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                ReadCandidates {
                    closest: vec![peer(9)],
                    known: vec![],
                }
            },
            |p| *p,
            |p, early| net.get(p, early, latency, p != peer(9), p == peer(9)),
            |error| *error == ReadError::Transport,
            Vec::new,
            || unreachable!("no peer is refused"),
            tokio::time::sleep,
        )
        .await;
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(start.elapsed(), Duration::from_millis(1500) + latency);
        let mut asked = net.gets.borrow().clone();
        asked.sort_unstable();
        assert_eq!(
            asked,
            vec![(peer(1), false), (peer(9), false)],
            "the second bootstrap peer waits for the first"
        );
        assert_eq!(net.most.get(), 2);
    }

    /// The browser's refusal hold-off, as these tests model it.
    const REFUSAL_COOLDOWN: Duration = Duration::from_secs(15);

    #[derive(Debug, PartialEq)]
    enum BusyRead {
        Busy,
    }

    /// Read `peer(0)` while `refusal` gives the time left on `holder`'s
    /// refusal at each instant. Discovery that starts while it is refused
    /// skips it and finds the next seven peers, which answer NotFound. Each
    /// discovery takes `round`.
    async fn read_past_refused_holder(
        holder: [u8; 32],
        refusal: impl Fn(tokio::time::Instant) -> Option<Duration>,
        round: Duration,
    ) -> (Result<Option<u8>, BusyRead>, usize) {
        let rounds = Cell::new(0);
        let refusal = &refusal;
        let result = retrieve_progressive(
            peer(0),
            0,
            Vec::new(),
            |_| {
                rounds.set(rounds.get() + 1);
                let closest = if refusal(tokio::time::Instant::now()).is_some() {
                    (2..=8).map(peer).collect()
                } else {
                    (1..=7).map(peer).collect()
                };
                async move {
                    tokio::time::sleep(round).await;
                    ReadCandidates {
                        closest,
                        known: vec![],
                    }
                }
            },
            |p| *p,
            |p, _| async move { Ok(if p == holder { Some(42) } else { None }) },
            |_| true,
            || {
                refusal(tokio::time::Instant::now())
                    .map(|remaining| (holder, remaining))
                    .into_iter()
                    .collect()
            },
            || BusyRead::Busy,
            tokio::time::sleep,
        )
        .await;
        (result, rounds.get())
    }

    /// A single refusal that ends at `until`.
    fn refused_until(
        until: tokio::time::Instant,
    ) -> impl Fn(tokio::time::Instant) -> Option<Duration> {
        move |now| {
            until
                .checked_duration_since(now)
                .filter(|remaining| !remaining.is_zero())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_holder_is_read_after_its_hold_off_rather_than_reported_absent() {
        let start = tokio::time::Instant::now();
        let (result, rounds) = read_past_refused_holder(
            peer(1),
            refused_until(start + REFUSAL_COOLDOWN),
            Duration::ZERO,
        )
        .await;
        // Seven NotFound answers would otherwise prove the record absent.
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(rounds, 2);
        assert_eq!(start.elapsed(), REFUSAL_COOLDOWN);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_that_ends_during_a_round_is_retried_after_the_usual_delay() {
        const ROUND: Duration = Duration::from_secs(2);
        let start = tokio::time::Instant::now();
        let (result, rounds) = read_past_refused_holder(
            peer(1),
            refused_until(start + Duration::from_secs(1)),
            ROUND,
        )
        .await;
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(rounds, 2);
        assert_eq!(start.elapsed(), ROUND + CLOSE_GROUP_RETRY_DELAY + ROUND);
    }

    #[tokio::test(start_paused = true)]
    async fn holders_that_keep_refusing_are_reported_busy_rather_than_absent() {
        let start = tokio::time::Instant::now();
        // Refused again on every attempt, so always a full hold-off away.
        let (result, rounds) =
            read_past_refused_holder(peer(1), |_| Some(REFUSAL_COOLDOWN), Duration::ZERO).await;
        assert_eq!(result, Err(BusyRead::Busy));
        assert_eq!(rounds, MAX_REFUSAL_WAITS + 1);
        let waits = u32::try_from(MAX_REFUSAL_WAITS).unwrap();
        assert_eq!(start.elapsed(), REFUSAL_COOLDOWN * waits);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_peer_beyond_the_close_group_does_not_delay_absence() {
        let start = tokio::time::Instant::now();
        let (result, rounds) =
            read_past_refused_holder(peer(200), |_| Some(REFUSAL_COOLDOWN), Duration::ZERO).await;
        assert_eq!(result, Ok(None));
        assert_eq!(rounds, 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[test]
    fn the_refusal_waits_are_three() {
        // Adopted with the 15 s refusal hold-off: three waits add at most 45 s.
        assert_eq!(MAX_REFUSAL_WAITS, 3);
    }

    #[test]
    fn failed_discovery_still_reads_known_holder() {
        let result = futures::executor::block_on(retrieve(
            peer(0),
            || async {
                ReadCandidates {
                    closest: vec![],
                    known: vec![peer(1)],
                }
            },
            |p| *p,
            |_| async { Ok::<_, ()>(Some(42)) },
            |_| true,
            |_| async {},
        ));
        assert_eq!(result, Ok(Some(42)));
    }

    #[test]
    fn native_retry_rules_include_thin_results_and_remote_failures() {
        for (count, remote_error, expected_rounds) in
            [(3, false, 2), (4, false, 1), (7, true, 2), (0, false, 2)]
        {
            let rounds = Cell::new(0);
            let sleeps = RefCell::new(Vec::new());
            let result = futures::executor::block_on(retrieve(
                peer(0),
                || {
                    rounds.set(rounds.get() + 1);
                    async move {
                        ReadCandidates {
                            closest: (0..count).map(peer).collect(),
                            known: vec![],
                        }
                    }
                },
                |p| *p,
                |_| async move {
                    if remote_error {
                        Err(())
                    } else {
                        Ok(None::<()>)
                    }
                },
                |_| true,
                |delay| {
                    sleeps.borrow_mut().push(delay);
                    async {}
                },
            ));
            assert_eq!(result, Ok(None));
            assert_eq!(rounds.get(), expected_rounds);
            assert_eq!(sleeps.borrow().len(), expected_rounds - 1);
        }
    }

    #[test]
    fn retry_rediscovers_and_can_find_a_new_holder() {
        let rounds = Cell::new(0);
        let result = futures::executor::block_on(retrieve(
            peer(0),
            || {
                rounds.set(rounds.get() + 1);
                let id = rounds.get();
                async move {
                    ReadCandidates {
                        closest: vec![peer(id)],
                        known: vec![],
                    }
                }
            },
            |p| *p,
            |p| async move { Ok::<_, ()>((p == peer(2)).then_some(42)) },
            |_| true,
            |_| async {},
        ));
        assert_eq!(result, Ok(Some(42)));
        assert_eq!(rounds.get(), 2);
    }
}
