//! Versions the workspace lock must keep, read from the committed `Cargo.lock`,
//! and the vendored saorsa-core it holds, which dials a peer's verified direct
//! address before its relay.

use ant_protocol::transport::{AddressType, DHTNode, MultiAddr, PeerId};

/// The lock's versions of `package`, one per copy in the build graph.
fn locked_versions(package: &str) -> Vec<String> {
    let lock = include_str!("../../Cargo.lock");
    let name = format!("name = \"{package}\"");
    let mut versions = Vec::new();
    let mut lines = lock.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line == name {
            if let Some(version) = lines
                .next()
                .and_then(|line| line.strip_prefix("version = \""))
                .and_then(|version| version.strip_suffix('"'))
            {
                versions.push(version.to_string());
            }
        }
    }
    versions
}

/// `version` as numbers, for comparing.
fn numbers(version: &str) -> Vec<u64> {
    version
        .split(['.', '-', '+'])
        .map_while(|part| part.parse().ok())
        .collect()
}

/// One saorsa-transport, at 0.38.2 or later: 0.38.2 reaps a QUIC reader task once
/// its connection ends, where 0.38.1 kept every past connection's reader allocated
/// for the life of the endpoint. The browser transport and the native network
/// library both build on it.
#[test]
fn the_lock_keeps_saorsa_transport_with_its_reader_task_fix() {
    let versions = locked_versions("saorsa-transport");
    assert_eq!(versions.len(), 1, "one saorsa-transport: {versions:?}");
    assert!(
        numbers(&versions[0]) >= numbers("0.38.2"),
        "saorsa-transport {} is older than 0.38.2",
        versions[0]
    );
}

/// One ant-protocol, the vendored copy with this network's price curve:
/// `[patch.crates-io]` puts vendor/ant-protocol in place of crates.io's, so the
/// lock holds it as a path package, without a `source`. ant-core requires
/// exactly that copy's version, so a fresh resolve, here or in a project that
/// takes ant-core by git and repeats the patch, can't pass it for a newer
/// crates.io release.
#[test]
fn the_lock_has_one_ant_protocol_the_vendored_copy() {
    let lock = include_str!("../../Cargo.lock");
    let entries: Vec<&str> = lock
        .split("[[package]]")
        .skip(1)
        .filter(|entry| entry.lines().any(|line| line == "name = \"ant-protocol\""))
        .collect();
    assert_eq!(entries.len(), 1, "one ant-protocol: {entries:?}");
    assert!(
        !entries[0].lines().any(|line| line.starts_with("source = ")),
        "ant-protocol is not the vendored copy: {}",
        entries[0]
    );

    let vendored = include_str!("../../vendor/ant-protocol/Cargo.toml")
        .lines()
        .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
        .expect("vendor/ant-protocol/Cargo.toml has a version");
    assert_eq!(locked_versions("ant-protocol"), [vendored]);
    let requirement = format!("ant-protocol = {{ version = \"={vendored}\",");
    assert!(
        include_str!("../Cargo.toml")
            .lines()
            .any(|line| line.starts_with(&requirement)),
        "ant-core/Cargo.toml doesn't require exactly ant-protocol {vendored}"
    );
}

/// The saorsa-core release vendor/saorsa-core is, and upstream's commit for it.
const SAORSA_CORE_VERSION: &str = "0.29.1";
const SAORSA_CORE_COMMIT: &str = "29bb069691880de59f5157c315a6233b1c57b20f";

/// One saorsa-core, the vendored copy: `[patch.crates-io]` puts
/// vendor/saorsa-core in place of crates.io's, so the lock holds it as a path
/// package, without a `source`. The copy is saorsa-core 0.29.1's crates.io
/// release with only the dial order changed (its VENDORED.md), built against
/// the lock's one saorsa-transport (see the saorsa-transport pin above).
#[test]
fn the_lock_has_one_saorsa_core_the_vendored_copy() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../../Cargo.toml")).expect("Cargo.toml is TOML");
    assert_eq!(
        manifest["patch"]["crates-io"]["saorsa-core"]["path"].as_str(),
        Some("vendor/saorsa-core"),
        "[patch.crates-io] must put vendor/saorsa-core in place of the crates.io release"
    );

    let lock = include_str!("../../Cargo.lock");
    let entries: Vec<&str> = lock
        .split("[[package]]")
        .skip(1)
        .filter(|entry| entry.lines().any(|line| line == "name = \"saorsa-core\""))
        .collect();
    assert_eq!(entries.len(), 1, "one saorsa-core: {entries:?}");
    assert!(
        !entries[0].lines().any(|line| line.starts_with("source = ")),
        "saorsa-core is not the vendored copy: {}",
        entries[0]
    );
    assert_eq!(locked_versions("saorsa-core"), [SAORSA_CORE_VERSION]);

    let vendored = include_str!("../../vendor/saorsa-core/Cargo.toml");
    let vendored: toml::Value =
        toml::from_str(vendored).expect("vendor/saorsa-core/Cargo.toml is TOML");
    assert_eq!(
        vendored["package"]["version"].as_str(),
        Some(SAORSA_CORE_VERSION)
    );
    let vcs = include_str!("../../vendor/saorsa-core/.cargo_vcs_info.json");
    assert!(
        vcs.contains(&format!("\"sha1\": \"{SAORSA_CORE_COMMIT}\"")),
        "vendor/saorsa-core is not saorsa-core {SAORSA_CORE_VERSION}'s release: {vcs}"
    );
}

/// The vendored copy dials a peer's verified direct address before its relay,
/// where upstream's dials the relay first. The client orders a peer's
/// addresses by `AddressType::priority` (`DHTNode::addresses_by_priority`), as
/// the network library's dial plan dials them: Direct, Relay, Unverified, Lan.
#[test]
fn a_verified_direct_address_is_dialled_before_a_relay() {
    assert!(AddressType::Direct.priority() < AddressType::Relay.priority());
    assert!(AddressType::Relay.priority() < AddressType::Unverified.priority());
    assert!(AddressType::Unverified.priority() < AddressType::Lan.priority());

    let entries = [
        ("/ip4/192.168.1.10/udp/9003/quic", AddressType::Lan),
        ("/ip6/2001:db8::9/udp/9002/quic", AddressType::Unverified),
        ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
        ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
    ];
    let address = |text: &str| text.parse::<MultiAddr>().expect("a valid address");
    let node = DHTNode {
        peer_id: PeerId::from_bytes([7u8; 32]),
        addresses: entries.iter().map(|&(text, _)| address(text)).collect(),
        address_types: entries.iter().map(|&(_, kind)| kind).collect(),
        distance: None,
        reliability: 1.0,
        address_authority: None,
    };
    assert_eq!(
        node.addresses_by_priority(),
        [
            "/ip4/203.0.113.7/udp/9001/quic",
            "/ip4/198.51.100.1/udp/9000/quic",
            "/ip6/2001:db8::9/udp/9002/quic",
            "/ip4/192.168.1.10/udp/9003/quic",
        ]
        .map(address)
    );
}

/// vendor/saorsa-core's own tests of the change, by file, each of which must
/// stay: the dial plan, the stored order, and the tag rank that keeps re-tagging
/// and the lookup's tie-break as upstream's.
const DIRECT_FIRST_TESTS: &[(&str, &str, &[&str])] = &[
    (
        "src/dht_network_manager.rs",
        include_str!("../../vendor/saorsa-core/src/dht_network_manager.rs"),
        &[
            "direct_first_direct_plus_relay_dials_direct_first",
            "direct_first_unverified_plus_relay_dials_relay_first",
            "direct_first_unverified_alone_is_still_dialled",
            "direct_first_full_order_direct_relay_unverified",
            "direct_first_same_wan_lan_stays_first",
            "direct_first_same_wan_relay_still_skipped",
            "direct_first_home_node_behind_nat_keeps_its_relay_first",
            "direct_first_lan_is_the_last_fallback",
            "direct_first_lookup_order_agrees_with_dial_order",
        ],
    ),
    (
        "src/dht/core_engine.rs",
        include_str!("../../vendor/saorsa-core/src/dht/core_engine.rs"),
        &[
            "address_type_priority_is_direct_relay_unverified_lan",
            "address_type_tag_rank_is_relay_direct_unverified_lan",
            "merge_typed_address_keeps_direct_before_relay",
            "upgrade_only_gossip_cannot_retag_relay_as_direct",
            "unsequenced_lookup_view_cannot_retag_relay_as_direct",
        ],
    ),
    (
        "src/client_routing.rs",
        include_str!("../../vendor/saorsa-core/src/client_routing.rs"),
        &["direct_first_leaves_the_lookup_tie_break_as_upstream_made_it"],
    ),
];

/// The vendored copy's tests of direct-first dialling are still there, and the
/// Build workflow runs its unit tests under this lock.
#[test]
fn the_direct_first_tests_stay_and_run() {
    for (path, source, names) in DIRECT_FIRST_TESTS {
        for name in *names {
            assert!(
                source.contains(&format!("fn {name}()")),
                "vendor/saorsa-core/{path} lost {name}, a test of direct-first dialling"
            );
        }
    }
    assert!(
        include_str!("../../.github/workflows/build.yml")
            .contains("run: cargo test --locked -p saorsa-core --lib"),
        "build.yml no longer runs vendor/saorsa-core's own tests"
    );
}

#[test]
fn versions_compare_by_number() {
    assert!(numbers("0.38.10") > numbers("0.38.2"));
    assert!(numbers("0.38.1") < numbers("0.38.2"));
    assert_eq!(numbers("0.23.0+ds.15"), vec![0, 23, 0]);
}
