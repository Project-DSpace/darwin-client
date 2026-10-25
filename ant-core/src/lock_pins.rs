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

#[test]
fn versions_compare_by_number() {
    assert!(numbers("0.38.10") > numbers("0.38.2"));
    assert!(numbers("0.38.1") < numbers("0.38.2"));
    assert_eq!(numbers("0.23.0+ds.15"), vec![0, 23, 0]);
}
