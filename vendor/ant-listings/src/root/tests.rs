//! The tree against the root vault's own test vectors, in `vectors/`, and
//! the vault's refusals of a wave.
//!
//! Every integer in the vector files is a 0x-prefixed hex string. A place or
//! leaf count that doesn't fit in a `u64` is past [`LEAF_LIMIT`] and past any
//! place in a wave, so it is checked as `u64::MAX`, which is too.

use super::*;
use crate::test_support::{bytes, list, number, payments, read_json, small};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The vector files' folder.
fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/root/vectors")
}

/// A vector file, by name.
fn read(name: &str) -> Value {
    read_json(vectors().join(name))
}

/// The wave files index.json lists, which are every wave file in the folder.
fn wave_files() -> Vec<String> {
    let index = read("index.json");
    let listed: Vec<String> = index["waves"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|name| name.as_str().expect("a name").to_string())
        .collect();
    let present: BTreeSet<String> = std::fs::read_dir(vectors())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("wave-"))
        .collect();
    assert_eq!(listed.iter().cloned().collect::<BTreeSet<_>>(), present);
    assert_eq!(listed.len(), present.len(), "a wave listed twice");
    listed
}

#[test]
fn leaf_pair_and_key_give_the_vectors_hashes() {
    let hashes = read("hashes.json");
    let leaves = hashes["leafVectors"].as_array().unwrap();
    assert!(!leaves.is_empty());
    for vector in leaves {
        assert_eq!(
            leaf(
                &bytes(&vector["quoteHash"]),
                &bytes(&vector["payee"]),
                &number(&vector["amount"])
            ),
            bytes::<32>(&vector["leaf"]),
            "{vector}"
        );
    }
    let pairs = hashes["pairVectors"].as_array().unwrap();
    assert!(!pairs.is_empty());
    for vector in pairs {
        assert_eq!(
            pair(&bytes(&vector["left"]), &bytes(&vector["right"])),
            bytes::<32>(&vector["pair"]),
            "{vector}"
        );
    }
    let keys = hashes["keyVectors"].as_array().unwrap();
    assert!(!keys.is_empty());
    for vector in keys {
        let leaf_count = small(&vector["leafCount"]);
        assert_ne!(leaf_count, u64::MAX);
        assert_eq!(
            key(
                &bytes(&vector["vault"]),
                &bytes(&vector["root"]),
                leaf_count
            ),
            bytes::<32>(&vector["key"]),
            "{vector}"
        );
    }
}

#[test]
fn waves_give_the_vectors_roots_keys_and_paths() {
    let vault: [u8; 20] = bytes(&read("index.json")["vault"]);
    let files = wave_files();
    assert!(files.len() > 20);
    for name in files {
        let file = read(&name);
        let payments = payments(&file);
        let leaf_count = small(&file["leafCount"]);
        assert_eq!(payments.len() as u64, leaf_count, "{name}");
        let leaves = list::<32>(&file["leaves"]);
        assert_eq!(
            payments.iter().map(RootPayment::leaf).collect::<Vec<_>>(),
            leaves,
            "{name}"
        );
        let root: [u8; 32] = bytes(&file["root"]);
        let recorded: [u8; 32] = bytes(&file["key"]);

        let wave = Wave::new(payments.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(wave.payments(), payments.as_slice());
        assert_eq!(wave.leaf_count(), leaf_count, "{name}");
        assert_eq!(wave.root(), root, "{name}");
        assert_eq!(wave.key(&vault), recorded, "{name}");
        assert_eq!(key(&vault, &root, leaf_count), recorded, "{name}");

        // The paths the file gives, exactly, and each leads to the key.
        let places = file["pathIndices"].as_array().unwrap();
        let paths = file["paths"].as_array().unwrap();
        assert!(!places.is_empty());
        assert_eq!(places.len(), paths.len());
        for (place, path) in places.iter().zip(paths) {
            let index = small(place);
            let at = usize::try_from(index).unwrap();
            let path = list::<32>(path);
            assert_eq!(wave.path(at), Some(path.clone()), "{name}, place {index}");
            assert!(path.len() <= MAX_PATH_LEN);
            assert_eq!(
                root_from_path(&leaves[at], index, leaf_count, &path),
                Some(root),
                "{name}, place {index}"
            );
            assert_eq!(
                leaf_key(&vault, &payments[at], index, leaf_count, &path),
                Some(recorded),
                "{name}, place {index}"
            );
        }
        // And every payment's own path leads to the root.
        for (at, leaf) in leaves.iter().enumerate() {
            let path = wave.path(at).unwrap();
            assert!(path.len() <= MAX_PATH_LEN);
            assert_eq!(
                root_from_path(leaf, at as u64, leaf_count, &path),
                Some(root),
                "{name}, place {at}"
            );
        }
        assert_eq!(wave.path(leaves.len()), None);
    }
}

#[test]
fn refused_places_leaf_counts_and_paths() {
    let refusals = read("refusals.json");
    let vault: [u8; 20] = bytes(&refusals["vault"]);
    assert_eq!(small(&refusals["leafLimit"]), LEAF_LIMIT);
    let cases = refusals["cases"].as_array().unwrap();
    assert!(cases.len() > 10);
    let mut seen = BTreeSet::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let file = read(case["wave"].as_str().unwrap());
        let wave = Wave::new(payments(&file)).unwrap();
        let recorded: [u8; 32] = bytes(&file["key"]);
        let own = usize::try_from(small(&case["leaf"])).unwrap();
        let leaf = list::<32>(&file["leaves"])[own];
        // The leaf's own place and path lead to the recorded key.
        assert_eq!(
            root_from_path(
                &leaf,
                own as u64,
                wave.leaf_count(),
                &wave.path(own).unwrap()
            ),
            Some(wave.root()),
            "{name}"
        );
        let index = small(&case["index"]);
        let leaf_count = small(&case["leafCount"]);
        let path = list::<32>(&case["path"]);
        let got = root_from_path(&leaf, index, leaf_count, &path);
        let refused_by = case["refusedBy"].as_str().unwrap();
        seen.insert(refused_by.to_string());
        match refused_by {
            "shape" => assert_eq!(got, None, "{name}"),
            "root" | "key" => {
                let root: [u8; 32] = bytes(&case["root"]);
                assert_eq!(got, Some(root), "{name}");
                assert_eq!(root == wave.root(), refused_by == "key", "{name}");
                let other = key(&vault, &root, leaf_count);
                assert_eq!(other, bytes::<32>(&case["key"]), "{name}");
                assert_ne!(other, recorded, "{name}");
            }
            other => panic!("{name}: refused by {other}"),
        }
    }
    assert_eq!(seen, ["key", "root", "shape"].map(String::from).into());
}

#[test]
fn the_topics_are_their_events_signatures() {
    let topic = |signature: &str| -> [u8; 32] { Keccak256::digest(signature.as_bytes()).into() };
    assert_eq!(
        topic("RootPaid(bytes32,address,uint256,uint256)"),
        ROOT_PAID_TOPIC
    );
    assert_eq!(topic("Transfer(address,address,uint256)"), TRANSFER_TOPIC);
}

#[test]
fn production_keys_name_the_production_vault() {
    let production = read_json(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/root/production-vectors.json"),
    );
    let vault: [u8; 20] = bytes(&production["productionVault"]);
    let vectors = production["keyVectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let file = read(vector["wave"].as_str().unwrap());
        let wave = Wave::new(payments(&file)).unwrap();
        assert_eq!(wave.root(), bytes::<32>(&vector["root"]), "{vector}");
        assert_eq!(wave.leaf_count(), small(&vector["leafCount"]), "{vector}");
        assert_eq!(wave.key(&vault), bytes::<32>(&vector["key"]), "{vector}");
        assert_ne!(wave.key(&vault), bytes::<32>(&file["key"]));
    }
}

#[test]
fn vector_files_name_nothing_outside_the_crate() {
    // The files describe the tree and their own fields, and name no file or
    // folder but their own: a copy that brings in text written for another
    // place fails here.
    let mut files =
        vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/root/production-vectors.json")];
    files.extend(
        std::fs::read_dir(vectors())
            .unwrap()
            .map(|entry| entry.unwrap().path()),
    );
    assert!(files.len() > 20);
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        for outside in ["script/", "root-vectors/", "public repos"] {
            assert!(!text.contains(outside), "{path:?} names {outside}");
        }
    }
}

#[test]
fn paths_hold_at_most_max_path_len_hashes() {
    // A path holds one hash for each level above the leaves.
    assert_eq!(1u64 << MAX_PATH_LEN, LEAF_LIMIT);
    let payments: Vec<RootPayment> = (1..=LEAF_LIMIT)
        .map(|n| payment(&n.to_be_bytes(), 0xaa, 1))
        .collect();
    let wave = Wave::new(payments).unwrap();
    assert!((0..512).all(|at| wave.path(at).unwrap().len() == MAX_PATH_LEN));
}

/// A payment whose quote hash ends in `tail`, paying `amount` to an address
/// of the byte `payee`.
fn payment(tail: &[u8], payee: u8, amount: u64) -> RootPayment {
    let mut quote_hash = [0; 32];
    quote_hash[32 - tail.len()..].copy_from_slice(tail);
    RootPayment {
        quote_hash,
        payee: [payee; 20],
        amount: Amount::from(amount),
    }
}

#[test]
fn waves_are_refused_as_the_vault_refuses_them() {
    use WaveError::*;
    let ok = |tail: u8| payment(&[tail], 0xaa, 5);
    let cases: Vec<(Vec<RootPayment>, WaveError)> = vec![
        (vec![], LeafCountOutOfRange(0)),
        (vec![payment(&[0], 0xaa, 5)], ZeroQuoteHash(0)),
        (vec![ok(1), ok(1)], RepeatedQuoteHash(1)),
        (vec![ok(2), ok(1)], QuoteHashesNotAscending(1)),
        // Zero is below anything before it, and named as zero.
        (vec![ok(1), payment(&[0], 0xaa, 5)], ZeroQuoteHash(1)),
        (vec![ok(1), payment(&[2], 0xaa, 0)], ZeroAmount(1)),
        (vec![ok(1), payment(&[2], 0x00, 5)], ZeroPayee(1)),
        // The quote hash is checked first, then the amount, then the payee.
        (vec![ok(1), payment(&[1], 0x00, 0)], RepeatedQuoteHash(1)),
        (vec![payment(&[1], 0x00, 0)], ZeroAmount(0)),
        // The first payment that fails is named.
        (
            vec![ok(1), payment(&[3], 0xaa, 0), payment(&[2], 0x00, 5)],
            ZeroAmount(1),
        ),
        // Quote hashes are ordered as big-endian numbers.
        (
            vec![payment(&[1, 0], 0xaa, 5), payment(&[0xff], 0xaa, 5)],
            QuoteHashesNotAscending(1),
        ),
    ];
    for (payments, error) in cases {
        assert_eq!(Wave::new(payments.clone()), Err(error), "{payments:?}");
    }
    assert!(Wave::new(vec![payment(&[0xff], 0xaa, 5), payment(&[1, 0], 0xaa, 5)]).is_ok());

    // At most the leaf limit.
    let many = |count: u64| {
        (1..=count)
            .map(|n| payment(&n.to_be_bytes(), 0xaa, 1))
            .collect()
    };
    assert_eq!(
        Wave::new(many(LEAF_LIMIT)).map(|wave| wave.leaf_count()),
        Ok(LEAF_LIMIT)
    );
    assert_eq!(
        Wave::new(many(LEAF_LIMIT + 1)),
        Err(LeafCountOutOfRange(513))
    );

    // The total fits in 256 bits, or the wave is refused at the payment
    // that passes it.
    let max = RootPayment {
        amount: Amount::MAX,
        ..ok(1)
    };
    assert_eq!(
        Wave::new(vec![max]).map(|wave| wave.total()),
        Ok(Amount::MAX)
    );
    assert_eq!(Wave::new(vec![max, ok(2)]), Err(TotalOverflow(1)));
    let half = RootPayment {
        amount: Amount::MAX / Amount::from(2) + Amount::from(1),
        ..ok(1)
    };
    assert_eq!(
        Wave::new(vec![
            half,
            RootPayment {
                quote_hash: ok(2).quote_hash,
                ..half
            }
        ]),
        Err(TotalOverflow(1))
    );
}

#[test]
fn sums_follow_the_order_payees_first_appear_in() {
    let wave = Wave::new(vec![
        payment(&[1], 0xb0, 1),
        payment(&[2], 0xa0, 2),
        payment(&[3], 0xb0, 4),
        payment(&[4], 0xc0, 8),
        payment(&[5], 0xa0, 16),
    ])
    .unwrap();
    assert_eq!(
        wave.sums(),
        [
            ([0xb0; 20], Amount::from(5)),
            ([0xa0; 20], Amount::from(18)),
            ([0xc0; 20], Amount::from(8)),
        ]
    );
    assert_eq!(wave.total(), Amount::from(31));
}

#[test]
fn a_wave_of_one_has_its_leaf_as_root_and_no_path() {
    let one = payment(&[7], 0xaa, 3);
    let wave = Wave::new(vec![one]).unwrap();
    assert_eq!(wave.root(), one.leaf());
    assert_eq!(wave.path(0), Some(Vec::new()));
    assert_eq!(wave.path(1), None);
    let vault = [0x42; 20];
    assert_eq!(
        leaf_key(&vault, &one, 0, 1, &[]),
        Some(key(&vault, &one.leaf(), 1))
    );
    assert_eq!(leaf_key(&vault, &one, 0, 1, &[one.leaf()]), None);
    assert_eq!(leaf_key(&vault, &one, 1, 1, &[]), None);
    assert_eq!(leaf_key(&vault, &one, 0, 0, &[]), None);
}

#[test]
fn a_path_checks_against_its_own_vault_only() {
    let wave = Wave::new(
        (1..=5u8)
            .map(|n| payment(&[n], 0xa0 + n, u64::from(n)))
            .collect(),
    )
    .unwrap();
    let path = wave.path(4).unwrap();
    // Five leaves: the last is carried up twice, and has one sibling.
    assert_eq!(path.len(), 1);
    let payment = wave.payments()[4];
    let ours = [0x42; 20];
    let theirs = [0x43; 20];
    assert_eq!(
        leaf_key(&ours, &payment, 4, 5, &path),
        Some(wave.key(&ours))
    );
    assert_ne!(wave.key(&ours), wave.key(&theirs));
    // Another amount or payee is another leaf.
    for other in [
        RootPayment {
            amount: payment.amount + Amount::from(1),
            ..payment
        },
        RootPayment {
            payee: [0x01; 20],
            ..payment
        },
    ] {
        assert_ne!(leaf_key(&ours, &other, 4, 5, &path), Some(wave.key(&ours)));
    }
}
