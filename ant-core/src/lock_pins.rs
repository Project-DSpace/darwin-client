//! Versions the workspace lock must keep, read from the committed `Cargo.lock`.

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

/// One ant-protocol, the vendored copy with this network's price multiplier:
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

#[test]
fn versions_compare_by_number() {
    assert!(numbers("0.38.10") > numbers("0.38.2"));
    assert!(numbers("0.38.1") < numbers("0.38.2"));
    assert_eq!(numbers("0.23.0+ds.15"), vec![0, 23, 0]);
}
