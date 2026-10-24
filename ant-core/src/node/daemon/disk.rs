//! Free disk space where node data lives, by partition.
//!
//! Nodes whose data directories share a filesystem partition share its free space, so disk space
//! is read per partition, and the fleet health ([`super::health`]) reports each partition's free
//! space. This module only reads.
//!
//! Upstream's manager also chose a node here for its disk-pressure eviction: on a partition at
//! 500 MiB free shared by two or more nodes, it stopped the node holding the least data and
//! deleted its data directory, with no check that the network held its records elsewhere. That
//! eviction is removed: no path of the node manager deletes a node's data.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Opaque identifier for the filesystem partition a path lives on.
///
/// On Unix this is the device id of the path (or its nearest existing ancestor); elsewhere it falls
/// back to the canonicalized path prefix. Two paths with the same key share free space.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionKey(String);

impl std::fmt::Display for PartitionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartitionKey {
    /// Construct a key with an arbitrary label. Test-only — real keys come from [`partition_key`].
    #[cfg(test)]
    pub(crate) fn for_test(label: &str) -> Self {
        PartitionKey(label.to_string())
    }
}

/// One partition that holds node data, and how much space is free on it.
#[derive(Debug, Clone)]
pub struct PartitionState {
    pub partition: PartitionKey,
    /// Free bytes available on the partition.
    pub available_bytes: u64,
}

/// Free bytes on the partition hosting `path` (or its nearest existing ancestor).
///
/// Returns `None` if the available space cannot be determined.
pub fn available_space(path: &Path) -> Option<u64> {
    let existing = nearest_existing_ancestor(path);
    fs2::available_space(&existing).ok()
}

/// The partitions the given node data directories live on, each with its free space, once each.
///
/// Partitions whose free space cannot be read are skipped.
pub fn partition_states<I>(data_dirs: I) -> Vec<PartitionState>
where
    I: IntoIterator<Item = PathBuf>,
{
    // One data directory per partition answers the free-space query for all of them.
    let mut probes: BTreeMap<PartitionKey, PathBuf> = BTreeMap::new();
    for data_dir in data_dirs {
        probes.entry(partition_key(&data_dir)).or_insert(data_dir);
    }

    probes
        .into_iter()
        .filter_map(|(partition, probe)| {
            let available_bytes = available_space(&probe)?;
            Some(PartitionState {
                partition,
                available_bytes,
            })
        })
        .collect()
}

/// Identify the partition a path lives on.
fn partition_key(path: &Path) -> PartitionKey {
    let existing = nearest_existing_ancestor(path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&existing) {
            return PartitionKey(format!("dev:{}", meta.dev()));
        }
    }

    // Fallback (and the non-Unix path): the canonicalized prefix is a reasonable partition proxy.
    let canon = std::fs::canonicalize(&existing).unwrap_or(existing);
    let key = canon
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_else(|| canon.to_string_lossy().into_owned());
    PartitionKey(key)
}

/// Walk up `path` until an existing directory/file is found, since a node's `data_dir` may not yet
/// exist. Falls back to the path itself if nothing exists.
fn nearest_existing_ancestor(path: &Path) -> PathBuf {
    let mut current = Some(path);
    while let Some(p) = current {
        if p.exists() {
            return p.to_path_buf();
        }
        current = p.parent();
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_states_reads_colocated_nodes_once() {
        // Two nodes under the same temp dir share a partition.
        let tmp = tempfile::tempdir().unwrap();
        let d1 = tmp.path().join("node-1");
        let d2 = tmp.path().join("node-2");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();

        let states = partition_states(vec![d1, d2]);
        assert_eq!(states.len(), 1, "co-located nodes share one partition");
        assert!(states[0].available_bytes > 0);
    }

    #[test]
    fn partition_states_reads_a_data_dir_not_created_yet() {
        // A node added but never started may have no data directory yet: its nearest existing
        // ancestor stands in for it.
        let tmp = tempfile::tempdir().unwrap();
        let states = partition_states(vec![tmp.path().join("nodes").join("node-9")]);
        assert_eq!(states.len(), 1);
        assert!(states[0].available_bytes > 0);
    }

    #[test]
    fn partition_states_of_no_nodes_is_empty() {
        assert!(partition_states(Vec::new()).is_empty());
    }

    #[test]
    fn reading_free_space_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let node = tmp.path().join("node-1");
        std::fs::create_dir_all(node.join("chunks")).unwrap();
        std::fs::write(node.join("chunks").join("record"), vec![1u8; 4096]).unwrap();

        partition_states(vec![node.clone()]);

        assert_eq!(
            std::fs::read(node.join("chunks").join("record")).unwrap(),
            vec![1u8; 4096]
        );
    }
}
