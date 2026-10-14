//! Native witnessed quote and storage-target policy, shared with browser I/O.

use ant_protocol::{CLOSE_GROUP_MAJORITY, CLOSE_GROUP_SIZE};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

pub(crate) const PUT_TARGET_WIDTH: usize = 20;
pub(crate) const SINGLE_NODE_WITNESSED_VIEW_COUNT: usize = 20;
pub(crate) const SINGLE_NODE_MIN_QUOTE_COUNT: usize = 1;

pub(crate) trait Peer: Copy + Eq + Ord + Hash {
    fn bytes(&self) -> &[u8; 32];
}
impl Peer for [u8; 32] {
    fn bytes(&self) -> &[u8; 32] {
        self
    }
}
impl Peer for ant_protocol::transport::PeerId {
    fn bytes(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

pub(crate) type Voters<K> = HashMap<K, HashSet<K>>;

#[derive(Debug, Clone)]
pub(crate) struct ResponderView<K> {
    pub(crate) responder: K,
    pub(crate) closest: Vec<K>,
}

pub(crate) fn distance<K: Peer>(peer: &K, address: &[u8; 32]) -> [u8; 32] {
    std::array::from_fn(|index| peer.bytes()[index] ^ address[index])
}

pub(crate) fn quote_launch_budget(successes: usize, in_flight: usize, remaining: usize) -> usize {
    CLOSE_GROUP_SIZE
        .saturating_sub(successes.saturating_add(in_flight))
        .min(remaining)
}

pub(crate) fn witness_quorum(missing_views: usize) -> usize {
    (CLOSE_GROUP_SIZE * 2)
        .div_ceil(3)
        .saturating_sub(missing_views)
        .max(1)
}

pub(crate) fn witness_votes<K: Peer>(views: &[ResponderView<K>]) -> Voters<K> {
    let mut voters: Voters<K> = HashMap::new();
    for view in views {
        for peer in &view.closest {
            voters.entry(*peer).or_default().insert(view.responder);
        }
    }
    voters
}

pub(crate) fn consensus_peers<K: Peer>(
    voters: &Voters<K>,
    address: &[u8; 32],
    quorum: usize,
) -> Vec<K> {
    let mut peers = voters
        .iter()
        .filter(|(_, votes)| votes.len() >= quorum)
        .map(|(peer, _)| *peer)
        .collect::<Vec<_>>();
    peers.sort_by(|a, b| {
        distance(a, address)
            .cmp(&distance(b, address))
            .then_with(|| voters[b].len().cmp(&voters[a].len()))
            .then_with(|| a.bytes().cmp(b.bytes()))
    });
    peers
}

pub(crate) fn validate_witnessed_peers(
    initial_count: usize,
    candidates: usize,
    required: usize,
) -> Result<(), String> {
    if candidates < required {
        return Err(format!("Witnessed close group inconclusive before payment: got {candidates}/{required} quorum-recognised peers."));
    }
    validate_initial_peers(initial_count)
}

/// Native witnessed-discovery contract: the requested initial responder count
/// must be satisfied. Try the 20-peer PUT neighbourhood, falling back to seven
/// on failure. Both attempts use the same transport lookup behavior.
pub(crate) async fn discover_put_peers<T, E, F, Fut>(
    discover: F,
    count: impl Fn(&T) -> usize,
    insufficient: impl Fn(usize, usize) -> E,
) -> Result<T, E>
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let validate = |result: T, width| {
        let found = count(&result);
        if found < width {
            Err(insufficient(found, width))
        } else {
            Ok(result)
        }
    };
    match discover(PUT_TARGET_WIDTH)
        .await
        .and_then(|result| validate(result, PUT_TARGET_WIDTH))
    {
        Ok(result) => Ok(result),
        Err(_) => discover(CLOSE_GROUP_SIZE)
            .await
            .and_then(|result| validate(result, CLOSE_GROUP_SIZE)),
    }
}

pub(crate) fn validate_initial_peers(initial_count: usize) -> Result<(), String> {
    if initial_count < CLOSE_GROUP_SIZE {
        return Err(format!("Witnessed close group returned only {initial_count}/{CLOSE_GROUP_SIZE} initial PUT peers before payment."));
    }
    Ok(())
}

/// Apply native self-inclusive view normalization to a raw transport response.
#[cfg(any(target_arch = "wasm32", test))]
#[cfg(test)]
pub(crate) fn normalize_view<K: Peer>(
    responder: K,
    mut closest: Vec<K>,
    address: &[u8; 32],
) -> ResponderView<K> {
    closest.push(responder);
    closest.sort_by_key(|peer| distance(peer, address));
    closest.dedup();
    closest.truncate(SINGLE_NODE_WITNESSED_VIEW_COUNT);
    ResponderView { responder, closest }
}

/// The closest seven initial peers supply votes; the wider initial set is
/// retained for PUT fallback. Missing views lower native's five-vote quorum.
pub(crate) fn scope_views<K: Peer>(
    initial: &[K],
    views: &[ResponderView<K>],
) -> Vec<ResponderView<K>> {
    let scope = initial
        .iter()
        .take(CLOSE_GROUP_SIZE)
        .copied()
        .collect::<HashSet<_>>();
    views
        .iter()
        .filter(|view| scope.contains(&view.responder))
        .cloned()
        .collect()
}

/// The peers claiming to hold the record among the closest `CLOSE_GROUP_SIZE`
/// valid responses, closest first. Only these claims count: the record is
/// already stored only if `CLOSE_GROUP_MAJORITY` of them prove it
/// ([`proven_by_majority`]).
pub(crate) fn counted_holders<K: Peer>(
    payable: impl IntoIterator<Item = K>,
    holders: impl IntoIterator<Item = K>,
    address: &[u8; 32],
) -> Vec<K> {
    let mut responses = payable
        .into_iter()
        .map(|peer| (false, peer))
        .chain(holders.into_iter().map(|peer| (true, peer)))
        .collect::<Vec<_>>();
    responses.sort_by_key(|response| distance(&response.1, address));
    responses
        .into_iter()
        .take(CLOSE_GROUP_SIZE)
        .filter(|response| response.0)
        .map(|response| response.1)
        .collect()
}

/// Whether `CLOSE_GROUP_MAJORITY` of `claimants` prove they hold a record.
/// Claimants are asked one at a time, in the order given, so at most one
/// proof is in flight; asking stops once that many have proved it, or once
/// too few are left to. A claimant whose proof fails, for whatever reason,
/// does not count.
pub(crate) async fn proven_by_majority<C, F, Fut>(claimants: Vec<C>, mut prove: F) -> bool
where
    F: FnMut(C) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut left = claimants.len();
    let mut proven = 0usize;
    for claimant in claimants {
        if proven + left < CLOSE_GROUP_MAJORITY {
            break;
        }
        left -= 1;
        if prove(claimant).await {
            proven += 1;
            if proven >= CLOSE_GROUP_MAJORITY {
                return true;
            }
        }
    }
    false
}

fn visit_subsets(
    quote_count: usize,
    subset_size: usize,
    start: usize,
    current: &mut Vec<usize>,
    visit: &mut impl FnMut(&[usize]),
) {
    if current.len() == subset_size {
        visit(current);
        return;
    }
    let last_start = quote_count - (subset_size - current.len());
    for index in start..=last_start {
        current.push(index);
        visit_subsets(quote_count, subset_size, index + 1, current, visit);
        current.pop();
    }
}

/// Return original quote indices in XOR order. Prefer the largest quote set,
/// then greatest support for its paid median, then closest subset on ties.
pub(crate) fn select_witnessed_quotes<K: Peer, P: Copy + Ord>(
    quotes: &[(K, P)],
    address: &[u8; 32],
    voters: &Voters<K>,
    required: usize,
) -> Option<Vec<usize>> {
    let mut order = (0..quotes.len()).collect::<Vec<_>>();
    order.sort_by_key(|&index| distance(&quotes[index].0, address));
    let max_count = CLOSE_GROUP_SIZE.min(quotes.len());
    for count in (SINGLE_NODE_MIN_QUOTE_COUNT..=max_count).rev() {
        let mut best: Option<(usize, Vec<usize>)> = None;
        visit_subsets(
            quotes.len(),
            count,
            0,
            &mut Vec::with_capacity(count),
            &mut |indices| {
                let prices = indices
                    .iter()
                    .map(|&index| quotes[order[index]].1)
                    .collect::<Vec<_>>();
                let Some(median) = crate::payment_policy::median_quote_index(&prices) else {
                    return;
                };
                let issuer = quotes[order[indices[median]]].0;
                let Some(support) = voters.get(&issuer).map(HashSet::len) else {
                    return;
                };
                if support < required {
                    return;
                }
                match &best {
                    Some((best_support, _)) if *best_support > support => {}
                    Some((best_support, previous))
                        if *best_support == support && previous.as_slice() <= indices => {}
                    _ => best = Some((support, indices.to_vec())),
                }
            },
        );
        if let Some((_, indices)) = best {
            return Some(indices.into_iter().map(|index| order[index]).collect());
        }
    }
    None
}

pub(crate) fn order_put_peers<K: Peer>(
    paid_issuer: K,
    peers: &[K],
    voters: &Voters<K>,
    required: usize,
) -> Option<Vec<K>> {
    let supporters = voters.get(&paid_issuer)?;
    let (mut supporting, fallback): (Vec<_>, Vec<_>) = peers
        .iter()
        .copied()
        .partition(|peer| supporters.contains(peer));
    if supporting.len() < required {
        return None;
    }
    supporting.extend(fallback);
    Some(supporting)
}

#[cfg(test)]
mod tests {
    #[test]
    fn upload_discovery_matches_native_requested_width_contract() {
        for first in [Ok(5usize), Err("lookup failed"), Ok(7), Ok(19), Ok(20)] {
            let calls = std::cell::RefCell::new(Vec::new());
            let result = futures::executor::block_on(super::discover_put_peers(
                |width| {
                    calls.borrow_mut().push(width);
                    std::future::ready(if width == 7 { Ok(7) } else { first })
                },
                |count| *count,
                |_, _| "insufficient peers",
            ))
            .unwrap();
            if first == Ok(20) {
                assert_eq!(result, 20);
                assert_eq!(*calls.borrow(), [20]);
            } else {
                assert_eq!(result, 7);
                assert_eq!(*calls.borrow(), [20, 7]);
            }
        }
        let result = futures::executor::block_on(super::discover_put_peers(
            |_| std::future::ready(Ok(5usize)),
            |count| *count,
            |found, width| (found, width),
        ));
        assert_eq!(result, Err((5, 7)));
    }

    use super::*;

    fn peer(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn witness_scope_deduplicates_votes_and_preserves_native_quorum() {
        let initial = (1..=20).map(peer).collect::<Vec<_>>();
        let views = (1..=20)
            .map(|n| normalize_view(peer(n), vec![peer(9); 8], &[0; 32]))
            .collect::<Vec<_>>();
        let scoped = scope_views(&initial, &views);
        assert_eq!(scoped.len(), 7);
        let voters = witness_votes(&scoped);
        assert_eq!(voters[&peer(9)].len(), 7);
        assert_eq!(voters[&peer(1)].len(), 1);
        assert_eq!(
            consensus_peers(&voters, &[0; 32], witness_quorum(0)),
            vec![peer(9)]
        );
        assert_eq!(
            (
                witness_quorum(0),
                witness_quorum(1),
                witness_quorum(2),
                witness_quorum(7)
            ),
            (5, 4, 3, 1)
        );
        assert!(validate_witnessed_peers(6, 1, 1).is_err());
        assert!(validate_witnessed_peers(7, 1, 1).is_ok());
        assert!(validate_witnessed_peers(7, 0, 1).is_err());
        let ordered = order_put_peers(peer(9), &initial, &voters, 5).unwrap();
        assert_eq!(ordered, initial);
        assert!(
            !ordered[..4].contains(&peer(9)),
            "native prioritizes witnesses, which need not include the issuer"
        );
    }

    #[test]
    fn full_and_portable_amounts_select_the_native_supported_subset() {
        use ant_protocol::{evm::Amount, transport::PeerId};
        let quotes = [(peer(1), 1_u128), (peer(2), 2), (peer(3), 3), (peer(4), 4)];
        let voters = HashMap::from([
            (peer(1), (1..=5).map(peer).collect()),
            (peer(2), (1..=5).map(peer).collect()),
            (peer(3), (1..=4).map(peer).collect()),
            (peer(4), (1..=5).map(peer).collect()),
        ]);
        // Four quotes would pay unsupported peer 3. The largest acceptable
        // subset is [1, 2, 3], whose upper median is the supported peer 2.
        let selected = select_witnessed_quotes(&quotes, &[0; 32], &voters, 5).unwrap();
        assert_eq!(selected, vec![0, 1, 2]);
        let native_quotes = quotes
            .iter()
            .map(|(peer, price)| (PeerId::from_bytes(*peer), Amount::from(*price)))
            .collect::<Vec<_>>();
        let native_voters = voters
            .into_iter()
            .map(|(peer, voters)| {
                (
                    PeerId::from_bytes(peer),
                    voters.into_iter().map(PeerId::from_bytes).collect(),
                )
            })
            .collect();
        assert_eq!(
            select_witnessed_quotes(&native_quotes, &[0; 32], &native_voters, 5),
            Some(selected)
        );
    }

    #[test]
    fn storage_votes_only_count_in_closest_seven_valid_responses() {
        assert!(counted_holders((1..=7).map(peer), (8..=11).map(peer), &[0; 32]).is_empty());
        assert_eq!(
            counted_holders((5..=7).map(peer), [4, 2, 3, 1].map(peer), &[0; 32]),
            (1..=4).map(peer).collect::<Vec<_>>(),
            "the claims counted, closest first"
        );
        assert_eq!(
            counted_holders((4..=7).map(peer), (1..=3).map(peer), &[0; 32]).len(),
            CLOSE_GROUP_MAJORITY - 1
        );
    }

    fn prove_with(results: &[bool]) -> (bool, Vec<usize>) {
        let asked = std::cell::RefCell::new(Vec::new());
        let proven = futures::executor::block_on(proven_by_majority(
            (0..results.len()).collect(),
            |claimant| {
                asked.borrow_mut().push(claimant);
                std::future::ready(results[claimant])
            },
        ));
        (proven, asked.into_inner())
    }

    #[test]
    fn a_claim_counts_only_once_a_majority_proves_it() {
        // Every claimant proves it: the first majority suffices.
        assert_eq!(prove_with(&[true; 7]), (true, vec![0, 1, 2, 3]));
        // Failed proofs don't count; later claimants make up for them.
        assert_eq!(
            prove_with(&[false, true, false, true, true, true, true]),
            (true, vec![0, 1, 2, 3, 4, 5])
        );
        // Asking stops as soon as a majority is out of reach.
        assert_eq!(
            prove_with(&[false, false, false, false, true, true, true]),
            (false, vec![0, 1, 2, 3])
        );
        assert_eq!(prove_with(&[true, true, true]), (false, Vec::new()));
        assert_eq!(prove_with(&[]), (false, Vec::new()));
        assert_eq!(
            prove_with(&[true, true, true, false]),
            (false, vec![0, 1, 2, 3])
        );
    }
}
