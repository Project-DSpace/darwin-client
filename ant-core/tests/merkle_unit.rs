//! Merkle payment unit tests.
//!
//! These tests exercise the free functions — `should_use_merkle` and the
//! batch partitioning that payment and cost estimation share — so no Client or
//! network is needed. The rest live in `src/data/client/merkle.rs` (inline test
//! module).
//!
//! darwin-node refuses batch payments, so the end-to-end tests can no longer
//! settle one; the arithmetic they checked against settlement is here: the
//! split either side of the 256-leaf boundary, the leaves an estimate bills
//! for the trees the upload engine builds, and the remainder an envelope is
//! paid with after the batches.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ant_core::data::client::merkle::{
    merkle_batch_partitions, merkle_batch_sizes, merkle_billable_leaves,
    merkle_upload_billable_units, merkle_upload_partitions, merkle_upload_split, should_use_merkle,
    MerkleUploadSplit, PaymentMode, DEFAULT_MERKLE_THRESHOLD, MERKLE_EXACT_MIN_BATCH,
};
use ant_protocol::evm::{MerkleTree, MAX_LEAVES};
use std::collections::HashSet;
use xor_name::XorName;

#[test]
fn test_threshold_constant() {
    assert_eq!(DEFAULT_MERKLE_THRESHOLD, 64);
}

#[test]
fn test_auto_mode() {
    assert!(!should_use_merkle(63, PaymentMode::Auto));
    assert!(should_use_merkle(64, PaymentMode::Auto));
}

#[test]
fn test_merkle_mode() {
    assert!(!should_use_merkle(1, PaymentMode::Merkle));
    assert!(should_use_merkle(2, PaymentMode::Merkle));
}

#[test]
fn test_single_mode() {
    assert!(!should_use_merkle(1000, PaymentMode::Single));
}

/// The client tells darwin-node's refusal of a batch payment apart from
/// other quote failures by the nodes' own sentence, and reports it as
/// `Error::BatchPaymentsRefused`, so its copy of the sentence must be the
/// node's word for word, at the darwin-node revision the tests run.
#[test]
fn the_clients_copy_of_the_batch_refusal_is_the_nodes() {
    assert_eq!(
        ant_core::data::BATCH_PAYMENTS_REFUSED,
        ant_node::payment::BATCH_PAYMENTS_REFUSED
    );
}

/// Counts covering the minimum tree, the merkle threshold, either side of a
/// full batch, and the `1 mod MAX_LEAVES` counts a naive `chunks(MAX_LEAVES)`
/// split turned into an unpayable one-address tail.
const PARTITION_CASES: [(usize, &[usize]); 10] = [
    (2, &[2]),
    (64, &[64]),
    (65, &[65]),
    (255, &[255]),
    (256, &[256]),
    (257, &[255, 2]),
    (300, &[256, 44]),
    (512, &[256, 256]),
    (513, &[256, 255, 2]),
    (769, &[256, 256, 255, 2]),
];

fn addresses(count: usize) -> Vec<[u8; 32]> {
    (0..count)
        .map(|i| {
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&(i as u64).to_be_bytes());
            addr
        })
        .collect()
}

#[test]
fn batch_sizes_rebalance_singleton_remainders() {
    for (total, expected) in PARTITION_CASES {
        assert_eq!(
            merkle_batch_sizes(total),
            expected,
            "{total} addresses must partition as {expected:?}, never with a one-address batch"
        );
    }
}

#[test]
fn batch_sizes_are_valid_tree_sizes_and_cover_the_input() {
    for total in 2..=(3 * MAX_LEAVES + 5) {
        let sizes = merkle_batch_sizes(total);
        assert_eq!(sizes.iter().sum::<usize>(), total);
        for size in sizes {
            assert!(
                (2..=MAX_LEAVES).contains(&size),
                "{total} addresses produced a batch of {size}, outside 2..={MAX_LEAVES}"
            );
        }
    }
}

#[test]
fn partitions_preserve_order_and_use_each_address_once() {
    for (total, expected) in PARTITION_CASES {
        let addrs = addresses(total);
        let partitions = merkle_batch_partitions(&addrs);

        let sizes: Vec<usize> = partitions.iter().map(|batch| batch.len()).collect();
        assert_eq!(sizes, expected);

        let flattened: Vec<[u8; 32]> = partitions.concat();
        assert_eq!(flattened, addrs, "{total}: order must be preserved");

        let unique: HashSet<[u8; 32]> = flattened.iter().copied().collect();
        assert_eq!(unique.len(), total, "{total}: no address may repeat");
    }
}

/// Leaves the vault bills for one tree of `batch`: the tree is padded to a
/// power of two, and a batch pays `median16 x 2^depth`.
fn billed_leaves(batch: &[[u8; 32]]) -> u64 {
    let leaves = batch.iter().map(|address| XorName(*address)).collect();
    let tree = MerkleTree::from_xornames(leaves).expect("a batch builds a tree");
    1u64 << tree.depth()
}

/// An estimate bills the leaves the vault charges for the trees the upload
/// engine builds, and one unit per chunk the engine pays per chunk. A
/// forced-merkle upload of 9 chunks is one tree, padded to 16 leaves; from
/// 32 chunks the engine builds exact power-of-two trees, so nothing is
/// padded. Checked for every count up to two full batches and past, the
/// 65- and 257-chunk boundaries among them.
#[test]
fn an_estimate_bills_the_leaves_of_the_trees_the_upload_engine_builds() {
    let nine = addresses(9);
    let batches = merkle_upload_partitions(9, &nine);
    assert_eq!(batches, vec![&nine[..]]);
    assert_eq!(billed_leaves(batches[0]), 16);
    assert_eq!(merkle_upload_billable_units(9), 16);
    assert_eq!(merkle_billable_leaves(9), 16);

    for chunks in 2..=(2 * MAX_LEAVES + 70) {
        let content = addresses(chunks);
        let batches = merkle_upload_partitions(chunks, &content);
        let batched: usize = batches.iter().map(|batch| batch.len()).sum();
        let billed = batches
            .iter()
            .map(|batch| billed_leaves(batch))
            .sum::<u64>()
            + (chunks - batched) as u64;
        assert_eq!(
            merkle_upload_billable_units(chunks as u64),
            billed,
            "{chunks} chunks: the estimate must bill what the batches and the remainder cost"
        );
    }
}

/// From 33 content records the upload engine pays the first 32 in one merkle
/// batch and leaves the last to be paid per chunk, the payment the envelope,
/// never in a batch, is paid in (`e2e_envelope` shows it joining the last
/// per-chunk payment on darwin-node). The batches always take the content in
/// order and leave fewer than `MERKLE_EXACT_MIN_BATCH` records, so the
/// remainder and the envelope come to at most 32 records.
#[test]
fn after_the_batches_the_remainder_left_for_the_envelope_is_under_32_records() {
    let content = addresses(33);
    assert_eq!(merkle_upload_partitions(33, &content), vec![&content[..32]]);
    assert_eq!(
        merkle_upload_split(33, 33),
        MerkleUploadSplit {
            batches: vec![32],
            per_chunk: 1,
        }
    );
    // Billed unpadded: 32 leaves and one chunk; an envelope is paid on top.
    assert_eq!(merkle_upload_billable_units(33), 33);

    for chunks in MERKLE_EXACT_MIN_BATCH..=(4 * MAX_LEAVES + 40) {
        let content = addresses(chunks);
        let batches = merkle_upload_partitions(chunks, &content);
        let batched: usize = batches.iter().map(|batch| batch.len()).sum();
        assert_eq!(batches.concat(), content[..batched], "{chunks} chunks");
        assert!(
            chunks - batched < MERKLE_EXACT_MIN_BATCH,
            "{chunks} chunks leave {} to pay per chunk",
            chunks - batched
        );
        assert_eq!(
            merkle_upload_split(chunks, chunks).per_chunk,
            chunks - batched
        );
    }
}

#[test]
fn billable_leaves_are_the_padded_partitions() {
    for (total, expected) in PARTITION_CASES {
        let padded: u64 = expected
            .iter()
            .map(|size| size.next_power_of_two() as u64)
            .sum();
        assert_eq!(
            merkle_billable_leaves(total as u64),
            padded,
            "{total} chunks must bill for the partition {expected:?}, padded"
        );
    }
}
