# Vendored from crates.io (saorsa-core 0.30.0, sha256 25e3b19c...; upstream commit 5fdeea2, as its .cargo_vcs_info.json names it;
# re-vendored from 0.29.1 with the merge of upstream node 0.24.0, the four patched files merged onto
# 0.30.0 without a conflict;
# MIT OR Apache-2.0, https://github.com/WithAutonomi/saorsa-core).
# The copy leaves out the crate's docs/, .github/, editor and agent settings and saved test output,
# none of which the build or the crate's tests read.
# The only change from upstream is the order a peer's addresses are dialled in: a verified Direct
# address before the relay. AddressType::priority (src/peer_record.rs) is Direct, Relay, Unverified,
# Lan; select_dial_candidates_with_context (src/dht_network_manager.rs) dials LAN first for a peer on
# our own WAN IP, then Direct, then the relay (still skipped on our own WAN IP), then Unverified, then
# LAN when nothing else is known; NodeInfo::merge_typed_address (src/dht/core_engine.rs) stores
# addresses in the same order. Weighing one view of a peer against another keeps upstream's order
# (AddressType::tag_rank: Relay, Direct, Unverified, Lan): a lookup hint can't re-tag a relay address
# as Direct, and the lookup's tie-break between reports (best_tier_priority, src/client_routing.rs)
# is unchanged.
# Upstream's tests that pinned relay first now pin direct first; the direct_first_* tests, the tag
# rank and re-tag tests in src/dht/core_engine.rs and the tie-break test in src/client_routing.rs
# are new. Drop this copy once an upstream release dials a verified direct address before a relay.

The copy's git objects. The Build workflow compares them with these on every
run, so a change to the copy is a change to this file too. The four patched
files are recorded one by one; the rest of the copy (every other file but this
one) is recorded as the sha256 of its `git ls-tree -r` lines. The rest is
crates.io 0.30.0's files unchanged, less what the copy leaves out (above);
0.30.0 itself dropped build.rs and tests/masque_relay_e2e.rs and added
src/dht_network_manager/closer_peers_tests.rs:

- src/client_routing.rs blob: 995f000c3c54e7e87b3d275738709ee6d018763d
- src/dht/core_engine.rs blob: e64a550e9f96500ed611238ca0a51f5c26de81ce
- src/dht_network_manager.rs blob: 6f07eadc5024e370ab7374924c9900b1bd12ec82
- src/peer_record.rs blob: 14424e2e3e4a9db62e619f221c642baa49dc720f
- rest sha256: f45b12c500438b307f3c47f20b4b24ee5d5f830554cbf208191a0ca449057274
